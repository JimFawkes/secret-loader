"""
    Think about caching the results to reduce the roudtrips to aws

    TODO: Add doc strings
"""
import base64
import dotenv
import boto3.session
from botocore.exceptions import ClientError

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
    def load(self, credential_name):
        raise NotImplementedError(f"A Loader needs to implement load(credential_name)")


class EnvLoader(BaseLoader):
    def __init__(self, getenv=os.getenv, *args, **kwargs):
        self.getenv = getenv

    def load(self, credential_name):
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

    def load(self, credential_name):
        self.load_env_file(self.file_path)
        return super().load(credential_name)


class AWSSecretsLoader(BaseLoader):
    # TODO: Fix TypeAnnotations
    # Not sure how to do type annotations for client
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

    def load(self, credential_name):
        try:
            return self._get_secret_value(credential_name)
        except ClientError as e:
            raise CredentialNotFoundError(
                f"Could not retrieve secret: {credential_name} from AWS SecretsManager"
            ) from e


# TODO: Think about renaming this class
class CredentialLoader(BaseClass):
    def __init__(self, loaders=[], *, parser=lambda x: x):
        self.loaders = self._construct_loader_list(loaders)
        self._parser = parser

    def __call__(self, credential_name, *, parser=None):
        if not self.loaders:
            raise NoLoaderConfiguredError(
                f"{self} has no loader configured, loaders={self.loaders}"
            )
        for loader in self.loaders:
            try:
                credential = loader.load(credential_name)
                return self.parse(credential, parser=parser)
            except CredentialNotFoundError as e:
                continue

        raise CredentialNotFoundError(
            f"Could not load '{credential_name}' using loaders: {self.loaders}"
        )

    # TODO: FIXME: loader has no type annotation, I am not sure which type to use
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

    # This could return multiple types (dict, str, int, float), dependent on the parser
    # TODO: How can I efficiently compose a return type for this situation?
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
