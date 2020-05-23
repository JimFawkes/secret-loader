"""
Copyright: (c) 2020, Moritz Eilfort
GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

This module contains the Loader clases for secret_loader
"""
import base64
import getpass
import logging
import os

import boto3.session
from botocore.exceptions import ClientError
import dotenv

from .base import BaseLoader, pretty_print_function
from .exceptions import SecretNotFoundError

logger = logging.getLogger("secret_loader.loaders")


class EnvLoader(BaseLoader):
    def __init__(self, getenv=os.getenv, *args, **kwargs):
        self.getenv = getenv

    def load(self, secret_name, **kwargs):
        logger.debug(f"Using {pretty_print_function(self.getenv)} to load environment variables")
        value = self.getenv(secret_name)
        if value is None:
            raise SecretNotFoundError(f"EnvLoader could not load {secret_name}")
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

    def load(self, secret_name, **kwargs):
        logger.debug(f"Using {pretty_print_function(self.load_env_file)} to load secrets from file")
        logger.debug(f"Trying to load secret from {self.file_path}")
        self.load_env_file(self.file_path)
        return super().load(secret_name)


class AWSSecretsLoader(BaseLoader):
    def __init__(self, client=None, region_name="eu-central-1"):
        self.client = client or self.get_client("secretsmanager", region_name)

    # aws.utils
    @staticmethod
    def get_client(service_name, region_name):
        session = boto3.session.Session()
        client = session.client(service_name=service_name, region_name=region_name)
        return client

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
            else:
                # UnrecognizedClientException: The security token included in the request is invalid.
                raise e

        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if "SecretString" in get_secret_value_response:
            return get_secret_value_response["SecretString"]
        else:
            return base64.b64decode(get_secret_value_response["SecretBinary"]).decode()

    def load(self, secret_name, **kwargs):
        try:
            return self._get_secret_value(secret_name)
        except ClientError as e:
            raise SecretNotFoundError(
                f"Could not retrieve secret: {secret_name} from AWS SecretsManager"
            ) from e


class InputLoader(BaseLoader):
    def __init__(self, input=getpass.getpass):
        self._input = input

    def load(self, secret_name, prompt_input=False, **kwargs):
        if prompt_input:
            logger.debug(f"Using {pretty_print_function(self._input)} to prompt the user for input")
            return self._input(f"Enter Value for {secret_name}: ")
        else:
            raise SecretNotFoundError(
                f"InputPrompt was set to '{prompt_input}' (default='False') for secret: {secret_name}."
            )
