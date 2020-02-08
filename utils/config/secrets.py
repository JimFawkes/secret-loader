"""
    Think about caching the results to reduce the roudtrips to aws

    TODO:
        - Add doc strings
        - Add Input Loader
            * Needs to be enabled differently because it might otherwise block
              the execution and change the behaviour
            * Add a flag when calling the credentials obj. to activate the user
              input option
            * This might be a time where a reorder or explicit loader ordering
              is important - Maybe per credential? Dynamic?
            * Set priorities for loaders?
            * Call loaders by name?


"""
import base64
import dotenv
import boto3.session
from botocore.exceptions import ClientError
import getpass

import warnings
import os

from collections.abc import Mapping
from pathlib import Path


# aws.utils
def get_client(service_name, region_name):
    session = boto3.session.Session()
    client = session.client(service_name=service_name, region_name=region_name)
    return client


class CredentialNotFoundError(Exception):
    """Could not load Credential"""


class NoLoaderConfiguredError(Exception):
    """No Loader was provided"""


class ConstructLoaderError(Exception):
    """Could not construct loader"""


class CredentialMutabilityError(Exception):
    """Encountered a mutable type"""


class BaseClass:
    def __repr__(self):
        attributes = ", ".join([f"{key}={value}" for key, value in vars(self).items()])
        return f"{self.__class__.__name__}({attributes})"


class BaseLoader(BaseClass):
    def load(self, credential_name, **kwargs):
        raise NotImplementedError(f"A Loader needs to implement load(credential_name)")


class EnvLoader(BaseLoader):
    def __init__(self, getenv=os.getenv, *args, **kwargs):
        self.getenv = getenv

    def load(self, credential_name, **kwargs):
        value = self.getenv(credential_name)
        if value is None:
            raise CredentialNotFoundError(f"EnvLoader could not load {credential_name}")
        return value


class EnvFileLoader(EnvLoader):
    def __init__(
        self,
        file_path=None,
        load_env_file=dotenv.load_dotenv,
        find_env_file=dotenv.find_dotenv,
        *args,
        **kwargs,
    ):

        self.find_env_file = find_env_file
        self.load_env_file = load_env_file
        self.file_path = file_path or self.find_env_file()

        super().__init__(os.getenv, *args, **kwargs)

    def load(self, credential_name, **kwargs):
        self.load_env_file(self.file_path)
        return super().load(credential_name)


class AWSSecretsLoader(BaseLoader):
    def __init__(self, client=None, region_name="eu-central-1"):
        self.client = client or get_client("secretsmanager", region_name)

    def _get_secret_value(self, secret_name):
        try:
            get_secret_value_response = self.client.get_secret_value(SecretId=secret_name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "DecryptionFailureException":
                # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
                # Deal with the exception here, and/or rethrow at your discretion.
                raise e
            elif e.response["Error"]["Code"] == "InternalServiceErrorException":
                # An error occurred on the server side.
                # Deal with the exception here, and/or rethrow at your discretion.
                raise e
            elif e.response["Error"]["Code"] == "InvalidParameterException":
                # You provided an invalid value for a parameter.
                # Deal with the exception here, and/or rethrow at your discretion.
                raise e
            elif e.response["Error"]["Code"] == "InvalidRequestException":
                # You provided a parameter value that is not valid for the current state of the resource.
                # Deal with the exception here, and/or rethrow at your discretion.
                raise e
            elif e.response["Error"]["Code"] == "ResourceNotFoundException":
                # We can't find the resource that you asked for.
                # Deal with the exception here, and/or rethrow at your discretion.
                raise e

        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if "SecretString" in get_secret_value_response:
            return get_secret_value_response["SecretString"]
        else:
            return base64.b64decode(get_secret_value_response["SecretBinary"]).decode()

    def load(self, credential_name, **kwargs):
        try:
            return self._get_secret_value(credential_name)
        except ClientError as e:
            raise CredentialNotFoundError(
                f"Could not retrieve secret: {credential_name} from AWS SecretsManager"
            ) from e


class InputLoader(BaseLoader):
    def __init__(self, input=getpass.getpass):
        self._input = input

    def load(self, credential_name, prompt_input=False, **kwargs):
        if prompt_input:
            return self._input(f"Enter Value for {credential_name}: ")
        else:
            raise CredentialNotFoundError(
                f"InputPrompt was set to '{prompt_input}' (default='False') for credential: {credential_name}."
            )


# TODO: Think about renaming this class
class CredentialLoader(BaseClass):
    def __init__(self, loaders=[], *, parser=lambda x: x):
        self.loaders = self._construct_loader_list(loaders)
        self._parser = parser

    def __call__(self, credential_name, *, parser=None, **kwargs):
        if not self.loaders:
            raise NoLoaderConfiguredError(
                f"{self} has no loader configured, loaders={self.loaders}"
            )
        for loader in self.loaders:
            try:
                credential = loader.load(credential_name, **kwargs)
                return self.parse(credential, parser=parser)
            except CredentialNotFoundError as e:
                continue

        raise CredentialNotFoundError(
            f"Could not load '{credential_name}' using loaders: {self.loaders}"
        )

    @staticmethod
    def _construct_loader(loader, *args, **kwargs):
        return loader(*args, **kwargs)

    @staticmethod
    def _construct_loader_list(loaders):
        loader_list = []
        for loader in loaders:
            if callable(loader):
                loader_list.append(CredentialLoader._construct_loader(loader))
            elif isinstance(loader, dict):
                loader_list.append(
                    CredentialLoader._construct_loader(
                        loader["loader"], *loader["args"], **loader["kwargs"]
                    )
                )
            elif isinstance(loader, tuple):
                loader_, args, kwargs = loader
                loader_list.append(CredentialLoader._construct_loader(loader_, *args, **kwargs))
            else:
                raise ConstructLoaderError(f"Could not construct loader for '{loader}'")

        return loader_list

    def parse(self, value, /, *, parser=None):
        if parser is None:
            return self._parser(value)
        else:
            return parser(value)

    def register(self, loader, *args, **kwargs):
        constructed_loader = self._construct_loader(loader, *args, **kwargs)
        self.loaders.insert(0, constructed_loader)


credential = CredentialLoader()
credential.register(AWSSecretsLoader)
credential.register(EnvFileLoader)
credential.register(EnvLoader)
