"""
v0.1
This module defines all interactions with sensitive credentials.
Specifically it defines:
    1. A container to store a single key/value pair [Credential]
    2. A container to store several key/value pairs [Credentials] (Review naming)
    3. Machinery to load credentials from different sources
------------------------------------------------------------------------------
v0.2
Usage:
    # config.py in some config file
    credential = CredentialLoaderFactory(
                    search_order=[
                        secrets.DictLoader,
                        secrets.EnvLoader,
                        secrets.EnvFileLoader,
                        secrets.AWSSecretsManagerLoader
                    ],
                    raise_failure=True
                ) # pass in other config

    api_password = credential("API_PASSWORD", default=None, raise_failure=False)
     - Try to laod credential in all places according to search order
     - For version v0.2 return plain text value, later maybe return
        Credential Object and allow reload or expiration or MetaData, maybe allow
        configuration in the loader to return plain text or credential object

    env_loader = EnvLoader(prefix="") # The prefix allways adds a prefix to the value name,
                                      # e.g., VALUE_NAME => AWS_VALUE_NAME with prefix="AWS_"
                                      # maybe in a later version enable case switch lower => capital
    value = env_loader.load("VALUE_NAME")

    DictLoader ?? How to deal with multiple secrets? Postpone dict loader for now
    EnvFileLoader(env_file, env_path) use py env loader


    Think about giving the factory a register method to register custom loaders.
    There could also be an attr to allow to ignore the rest (potential race-condition?)

    how should the default env loader list be defined?
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
from typing import Union, Generator, Any, List, Callable
from pathlib import Path


# aws.utils
def get_client(service_name: str, region_name: str):
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
    def load(self, credential_name: str) -> str:
        raise NotImplementedError(f"A Loader needs to implement load(credential_name)")


class EnvLoader(BaseLoader):
    def __init__(self, getenv: Callable = os.getenv, *args: tuple, **kwargs: dict) -> None:
        self.getenv = getenv

    def load(self, credential_name: str) -> str:
        value = self.getenv(credential_name)
        if value is None:
            raise CredentialNotFoundError(f"EnvLoader could not load {credential_name}")
        return value


class EnvFileLoader(EnvLoader):
    def __init__(
        self,
        file_path: Union[str, Path, None] = None,
        load_env_file: Callable = dotenv.load_dotenv,
        find_env_file: Callable = dotenv.find_dotenv,
        *args: tuple,
        **kwargs: dict,
    ) -> None:

        self.find_env_file = find_env_file
        self.load_env_file = load_env_file
        self.file_path = file_path or self.find_env_file()

        self.load_env_file(self.file_path)

        super().__init__(os.getenv, *args, **kwargs)


class AWSSecretsLoader(BaseLoader):
    # TODO: Fix TypeAnnotations
    # Not sure how to do type annotations for client
    def __init__(self, client=None, region_name: str = "eu-central-1") -> None:
        self.client = client or get_client("secretsmanager", region_name)

    def _get_secret_value(self, secret_name: str) -> str:
        try:
            get_secret_value_response: dict = self.client.get_secret_value(SecretId=secret_name)
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
        else:
            # Decrypts secret using the associated KMS CMK.
            # Depending on whether the secret is a string or binary, one of these fields will be populated.
            if "SecretString" in get_secret_value_response:
                return get_secret_value_response["SecretString"]
            else:
                return base64.b64decode(get_secret_value_response["SecretBinary"])

    def load(self, credential_name: str) -> str:
        try:
            return self._get_secret_value(credential_name)
        except ClientError as e:
            raise CredentialNotFoundError(
                f"Could not retrieve secret: {credential_name} from AWS SecretsManager"
            ) from e


# Should the default list, be a global var?
# Should the default list contain instances or classes that get instatiated?
# NOTE: NOT TESTED
# TODO: Refactor and/or write tests
# DEFAULT_LOADERS = [EnvLoader]


# TODO: Think about renaming this class
class CredentialLoader(BaseClass):
    def __init__(self, loaders: list = [], *, parser: Callable = lambda x: x) -> None:
        self.loaders: List[BaseLoader] = self._construct_loader_list(loaders)
        self._parser: Callable = parser

    def __call__(self, credential_name: str, *, parser: Union[Callable, None] = None) -> str:
        if not self.loaders:
            raise NoLoaderConfiguredError(f"{self} has no loader configured, loaders={self.loaders}")
        for loader in self.loaders:
            try:
                credential: str = loader.load(credential_name)
                return self.parse(credential, parser=parser)
            except CredentialNotFoundError as e:
                continue

        raise CredentialNotFoundError(f"Could not load '{credential_name}' using loaders: {self.loaders}")

    # TODO: FIXME: loader has no type annotation, I am not sure which type to use
    @staticmethod
    def _construct_loader(name: str, loader, *args: Any, **kwargs: Any) -> BaseLoader:
        return loader(*args, **kwargs)

    @staticmethod
    def _construct_loader_list(loaders: Union[list, tuple]) -> list:
        loader_list: list = []
        for loader in loaders:
            if callable(loader):
                loader_list.append(CredentialLoader._construct_loader("", loader))
            elif isinstance(loader, dict):
                loader_list.append(
                    CredentialLoader._construct_loader(
                        loader["name"], loader["loader"], *loader["args"], **loader["kwargs"]
                    )
                )
            elif isinstance(loader, tuple):
                name, loader_, args, kwargs = loader
                loader_list.append(CredentialLoader._construct_loader(name, loader_, *args, **kwargs))
            else:
                raise ConstructLoaderError(f"Could not construct loader for '{loader}'")

        return loader_list

    # This could return multiple types (dict, str, int, float), dependent on the parser
    # TODO: How can I efficiently compose a return type for this situation?
    def parse(self, value, /, *, parser: Union[Callable, None] = None):
        if parser is None:
            return self._parser(value)
        else:
            return parser(value)

    def register(self, name: str, loader: BaseLoader, *args: Any, **kwargs: Any) -> None:
        constructed_loader = self._construct_loader(name, loader, *args, **kwargs)
        self.loaders.insert(0, constructed_loader)


credential = CredentialLoader([EnvLoader])

# class Credential(Mapping):
#     """Store a single Credential in the form of a key/value pair"""
#
#     def __init__(self, name: str, secret: Union[int, str]) -> None:
#         """
#         Construct the Credential.
#
#         Only allow certain immutable types as name and secret, to not allow any,
#         changes to the values.
#         """
#         if isinstance(name, str):
#             self._name: str = name
#         else:
#             raise CredentialMutabilityError(
#                 f"Credential.name only accepts variables of type str, not {type(name)}"
#             )
#         if isinstance(secret, (int, str)):
#             self._secret: Union[int, str] = secret
#         else:
#             raise CredentialMutabilityError(
#                 f"Credential.secret only accepts variables of types [str, tuple], not {type(name)}"
#             )
#
#     def __repr__(self) -> str:
#         return f"Credential(name={self.name}, secret=***)"
#
#     def __getitem__(self, key: str) -> Union[int, str]:
#         if key == self.name:
#             return self._secret
#         else:
#             raise KeyError(f"Credential has no key {key}")
#
#     def __iter__(self) -> Generator[str, None, None]:
#         yield self.name
#
#     def __len__(self) -> int:
#         return 1
#
#     @property
#     def name(self) -> str:
#         return self._name
#
#     @property
#     def secret(self) -> str:
#         return "***"
#
#     def reveal(self) -> Union[int, str]:
#         return self._secret
#

# class Credentials(Mapping):
#     """Store a list of credentials and provide the machinery to load them."""
#
#     # TODO: Review keys(), items(), values(), get()
#     # TODO: Review if getitem should return Credential or the revealed secret
#
#     def __init__(self) -> None:
#         self._secrets: dict = {}
#
#     def __getitem__(self, key: str) -> Union[int, str]:
#         return self._secrets[key].reveal()
#
#     def __iter__(self) -> Generator[str, None, None]:
#         for key in self._secrets.keys():
#             yield key
#
#     def __len__(self) -> int:
#         return len(self._secrets)
#
#     def __repr__(self):
#         return f"Credentials()"
#
#     def load(self, secret: dict) -> Union[int]:
#         if not isinstance(secret, dict):
#             raise NotImplementedError(f"Currently only supporting dicts")
#
#         if not secret:
#             return 0
#
#         inserted_secrets: int = 0
#         for key, value in secret.items():
#             self._secrets[key] = Credential(name=key, secret=value)
#             inserted_secrets += 1
#
#         return inserted_secrets
