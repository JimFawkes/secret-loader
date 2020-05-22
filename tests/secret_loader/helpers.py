"""
Copyright: (c) 2020, Moritz Eilfort
GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

This module contains helper functions and classes for the tests
"""
import base64
import datetime

import boto3
import botocore.session
from botocore.stub import Stubber, ANY
import pytest

from secret_loader.base import BaseLoader
from secret_loader.exceptions import SecretNotFoundError
from secret_loader import cli


ENV_VAR_NAME = "TEST_SECRET_NAME"
ENV_VAR_VALUE = "SECRET_VALUE"

ENV_FILE_CONTENT = f"""
{ENV_VAR_NAME}={ENV_VAR_VALUE}
"""

SM_RESPONSE_TEMPLATE = {
    "ARN": f"arn:aws:secretsmanager:eu-central-1:123567891234:secret:{ENV_VAR_NAME}-AbCdEf",
    "Name": ENV_VAR_NAME,
    "VersionId": "1a2bcd34-efab-5c67-89d1-234f5a6b78c9",
    "SecretString": ENV_VAR_VALUE,
    "VersionStages": ["AWSCURRENT"],
    "CreatedDate": datetime.datetime(2020, 1, 19, 15, 17, 10, 957000),
    "ResponseMetadata": {
        "RequestId": "1ab2cd34-5e67-891f-23ab-45c6d78ef9a1",
        "HTTPStatusCode": 200,
        "HTTPHeaders": {
            "date": "Wed, 01 Jan 2020 01:23:45 GMT",
            "content-type": "application/x-amz-json-1.1",
            "content-length": "363",
            "connection": "keep-alive",
            "x-amzn-requestid": "1ab2cd34-5e67-891f-23ab-45c6d78ef9a1",
        },
        "RetryAttempts": 0,
    },
}


SM_BINARY_RESPONSE_TEMPLATE = {
    "ARN": f"arn:aws:secretsmanager:eu-central-1:123567891234:secret:{ENV_VAR_NAME}-AbCdEf",
    "Name": ENV_VAR_NAME,
    "VersionId": "1a2bcd34-efab-5c67-89d1-234f5a6b78c9",
    "SecretBinary": base64.b64encode(ENV_VAR_VALUE.encode()),
    "VersionStages": ["AWSCURRENT"],
    "CreatedDate": datetime.datetime(2020, 1, 19, 15, 17, 10, 957000),
    "ResponseMetadata": {
        "RequestId": "1ab2cd34-5e67-891f-23ab-45c6d78ef9a1",
        "HTTPStatusCode": 200,
        "HTTPHeaders": {
            "date": "Wed, 01 Jan 2020 01:23:45 GMT",
            "content-type": "application/x-amz-json-1.1",
            "content-length": "363",
            "connection": "keep-alive",
            "x-amzn-requestid": "1ab2cd34-5e67-891f-23ab-45c6d78ef9a1",
        },
        "RetryAttempts": 0,
    },
}
SM_EXPECTED_PARAMS = {"SecretId": ANY}


# TODO: Make these two stub helper methods into context managers
def get_stubbed_boto_client_response(
    service_name="secretsmanager",
    region_name="eu-central-1",
    method_name="get_secret_value",
    response=SM_RESPONSE_TEMPLATE,
    expected_params=SM_EXPECTED_PARAMS,
):
    client = botocore.session.get_session().create_client(service_name, region_name)

    stub = Stubber(client)
    stub.add_response(method_name, response, expected_params)
    stub.activate()

    return client


def get_stubbed_boto_client_error(
    service_name="secretsmanager",
    region_name="eu-central-1",
    method_name="get_secret_value",
    response=SM_RESPONSE_TEMPLATE,
    expected_params=SM_EXPECTED_PARAMS,
    service_error_code="InvalidParameterException",
):
    client = botocore.session.get_session().create_client(service_name, region_name)

    stub = Stubber(client)
    stub.add_client_error(
        method=method_name, expected_params=expected_params, service_error_code=service_error_code
    )
    stub.activate()

    return client


@pytest.fixture(
    params=[
        "DecryptionFailureException",
        "InternalServiceErrorException",
        "InvalidParameterException",
        "InvalidRequestException",
        "ResourceNotFoundException",
        "UnrecognizedClientException",
    ]
)
def sm_client_error(request):
    return get_stubbed_boto_client_error(service_error_code=request.param)


@pytest.fixture(params=[SM_RESPONSE_TEMPLATE, SM_BINARY_RESPONSE_TEMPLATE])
def sm_client_response(request):
    return get_stubbed_boto_client_response(response=request.param)


def dummy_load_env_file(filepath, *args, **kwargs):
    return None


def dummy_find_env_file(*args, **kwargs):
    return None


class DummyLoader(BaseLoader):
    def __init__(self, raise_not_found=False):
        self.raise_not_found = raise_not_found

    def load(self, secret_name, **kwargs):

        if self.raise_not_found:
            raise SecretNotFoundError(f"DummyLoader raise_not_found=True")

        if secret_name is None:
            raise SecretNotFoundError(f"DummyLoader encountered a None Value")

        return secret_name


# ----------------------------------------------------------------------------
# CLI Helpers
# ----------------------------------------------------------------------------


class MockArgs:
    def __init__(
        self,
        name="",
        fail=False,
        loader=None,
        custom_loader=None,
        list_loaders=False,
        secret=None,
        priority=cli.DEFAULT_PRIORITY,
        remove_loaders=False,
        **kwargs,
    ):
        self.name = name
        self.fail = fail
        self.loader = loader
        self.custom_loader = custom_loader
        self.list_loaders = list_loaders
        self.secret = secret
        self.priority = float(priority)
        self.remove_loaders = remove_loaders


@pytest.fixture
def get_parse_args(monkeypatch):

    monkeypatch.setattr(cli, "get_secret_loader", lambda x: lambda x: x)
    monkeypatch.setattr(cli, "list_loaders", lambda x: None)

    def parse_args(args=[]):
        return cli.parse_args(cli.parser.parse_args(args))

    return parse_args


@pytest.fixture
def valid_loader_class():
    return list(cli.available_loaders)[0]


@pytest.fixture
def valid_loader(valid_loader_class):
    return cli.available_loaders[valid_loader_class]
