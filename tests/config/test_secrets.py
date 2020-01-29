import pytest
import os

from contextlib import contextmanager

import boto3

import botocore.session
from botocore.stub import Stubber, ANY
import datetime

from utils.config import secrets


# TODO: Move the appropriate things to a base file
# TODO: Refacotr tests
# TODO: Use fixtures
# TODO: Use parameterized fixtures to not repeat so much
# TODO: Add docstrings

ENV_VAR_NAME = "TEST_CREDENTIAL_NAME"
ENV_VAR_VALUE = "SECRET_VALUE"

ENV_FILE_CONTENT = f"""
{ENV_VAR_NAME}={ENV_VAR_VALUE}
"""

SM_RESPONSE_TEMPLATE = {
    "ARN": f"arn:aws:secretsmanager:eu-central-1:123567891234:secret:{ENV_VAR_NAME}-AbCdEf",
    "Name": ENV_VAR_NAME,
    "VersionId": "1a2bcd34-efab-5c67-89d1-234f5a6b78c9",
    # "SecretString": '{"eu":{"USR":"eu_user_name","PW":"eu_password"},"us":{"USR":"us_user_name","PW":"us_password"}}',
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

    stub.assert_no_pending_responses()
    stub.deactivate()


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
    stub.add_client_error(method=method_name, expected_params=expected_params, service_error_code=service_error_code)
    stub.activate()

    return client


def dummy_load_env_file(filepath, *args, **kwargs):
    os.environ[ENV_VAR_NAME] = ENV_VAR_VALUE
    return None


def dummy_find_env_file(*args, **kwargs):
    return None


# NOTE: This is a very weak and strange test. I could not come up with a better
# solution for this. Please refactor ASAP.
def test_get_stubbed_boto_client_response():
    service_name = "secretsmanager"
    region_name = "eu-central-1"

    client = get_stubbed_boto_client_response(service_name, region_name)
    client_type_str = str(client.__class__).lower()
    assert f"<class 'botocore.client.{service_name}'>" == client_type_str


def test_get_stubbed_boto_client_error():
    service_name = "secretsmanager"
    region_name = "eu-central-1"

    client = get_stubbed_boto_client_error(service_name, region_name)
    client_type_str = str(client.__class__).lower()
    assert f"<class 'botocore.client.{service_name}'>" == client_type_str


# NOTE: This is a very weak and strange test. I could not come up with a better
# solution for this. Please refactor ASAP.
def test_get_client():
    service_name = "secretsmanager"
    region_name = "eu-central-1"

    client = secrets.get_client(service_name, region_name)
    client_type_str = str(client.__class__).lower()

    assert f"<class 'botocore.client.{service_name}'>" == client_type_str


# ----------------------------------------------------------------------------
# Test BaseClass
# ----------------------------------------------------------------------------


def test_base_class_has_repr():
    base_class = secrets.BaseClass()

    assert "BaseClass()" == str(base_class)


# ----------------------------------------------------------------------------
# Test BaseLoader
# ----------------------------------------------------------------------------


def test_base_loader_exists():
    base_loader = secrets.BaseLoader()

    assert base_loader is not None
    assert isinstance(base_loader, secrets.BaseLoader)


def test_base_loader_has_load_method():
    base_loader = secrets.BaseLoader()

    with pytest.raises(NotImplementedError):
        base_loader.load("SOME_VAR")


def test_base_loader_load_method_requires_attribute():
    base_loader = secrets.BaseLoader()

    with pytest.raises(TypeError):
        base_loader.load()


def test_base_loader_has_repr():
    base_loader = secrets.BaseLoader()

    assert "BaseLoader(" in str(base_loader)


# ----------------------------------------------------------------------------
# Test DumyLoader
# ----------------------------------------------------------------------------


class DummyLoader(secrets.BaseLoader):
    def __init__(self, raise_not_found=False):
        self.raise_not_found = raise_not_found

    def load(self, credential_name):

        if self.raise_not_found:
            raise secrets.CredentialNotFoundError(f"DummyLoader raise_not_found=True")

        if credential_name is None:
            raise secrets.CredentialNotFoundError(f"DummyLoader encountered a None Value")

        return credential_name


def test_dummy_loader_exists():
    dummy_loader = DummyLoader()

    assert dummy_loader is not None
    assert isinstance(dummy_loader, DummyLoader)


def test_dummy_loader_load_variable():
    dummy_loader = DummyLoader()
    dummy_var_name = "MY_TEST_ENV_VAR"

    value = dummy_loader.load(dummy_var_name)

    assert value == dummy_var_name


def test_dummy_loader_fail_for_none():
    dummy_loader = DummyLoader()

    with pytest.raises(secrets.CredentialNotFoundError):
        value = dummy_loader.load(None)


def test_dummy_loader_fail_if_forced():
    dummy_loader = DummyLoader(raise_not_found=True)

    with pytest.raises(secrets.CredentialNotFoundError) as exception_info:
        value = dummy_loader.load("some_var")

    assert "raise_not_found" in str(exception_info.value)


# ----------------------------------------------------------------------------
# Test EnvLoader
# ----------------------------------------------------------------------------


def test_env_loader_exists():
    env_loader = secrets.EnvLoader()

    assert env_loader is not None
    assert isinstance(env_loader, secrets.EnvLoader)


def test_env_loader_load_env_variable():
    env_loader = secrets.EnvLoader()

    env_var_name = "MY_TEST_ENV_VAR"
    env_var_value = "some_value"
    os.environ[env_var_name] = env_var_value

    value = env_loader.load(env_var_name)

    # Remove side-effects for other tests
    # TODO: Check if there is a better way to do this
    del os.environ[env_var_name]

    assert value == env_var_value


def test_env_loader_fail_for_none_existing_variable():
    env_loader = secrets.EnvLoader()

    env_var_name = "MY_TEST_ENV_VAR"

    with pytest.raises(secrets.CredentialNotFoundError):
        value = env_loader.load(env_var_name)


# The default value should only be used after checking all loaders
# Implement on CredentialLoader returned by Factory
# def test_env_loader_use_default_for_none_existing_variable():
#     env_loader = secrets.EnvLoader()
#
#     env_var_name = "MY_TEST_ENV_VAR"
#     default_env_var = "some_default_value"
#
#     value = env_loader.load(env_var_name, default=default_env_var)
#     assert value == default_env_var

# ----------------------------------------------------------------------------
# Test EnvFileLoader
# ----------------------------------------------------------------------------


def test_env_file_loader_exists():
    env_file_loader = secrets.EnvFileLoader()
    assert env_file_loader is not None


def test_env_file_loader_value_from_file(tmp_path):
    tmp_dir = tmp_path / "tmp_env"
    tmp_dir.mkdir()
    tmp_file = tmp_dir / ".env"
    tmp_file.write_text(ENV_FILE_CONTENT)

    env_file_loader = secrets.EnvFileLoader(file_path=tmp_file)
    value = env_file_loader.load(ENV_VAR_NAME)

    assert value == ENV_VAR_VALUE


def test_env_file_loader_fail_for_none_exisiting_variable(tmp_path):
    tmp_dir = tmp_path / "tmp_env"
    tmp_dir.mkdir()
    tmp_file = tmp_dir / ".env"
    tmp_file.write_text(ENV_FILE_CONTENT)

    env_file_loader = secrets.EnvFileLoader(file_path=tmp_file)
    with pytest.raises(secrets.CredentialNotFoundError):
        value = env_file_loader.load("UNKNOWN_CREDENTIAL")


def test_env_file_loader_with_dummy_callables():
    env_file_loader = secrets.EnvFileLoader(dummy_load_env_file, dummy_find_env_file)
    value = env_file_loader.load(ENV_VAR_NAME)

    assert value == ENV_VAR_VALUE

    del os.environ[ENV_VAR_NAME]


# ----------------------------------------------------------------------------
# Test AWSSecretsManagerLoader
# ----------------------------------------------------------------------------


def test_aws_secrets_loader_exists():
    aws_secrets_loader = secrets.AWSSecretsLoader()
    assert aws_secrets_loader is not None


def test_aws_secrets_loader_takes_client():

    client = get_stubbed_boto_client_response()
    aws_secrets_loader = secrets.AWSSecretsLoader(client=client)
    assert aws_secrets_loader.client is client


def test_aws_secrets_loader_get_secret_value():
    client = get_stubbed_boto_client_response()
    aws_secrets_loader = secrets.AWSSecretsLoader(client=client)
    value = aws_secrets_loader.load(ENV_VAR_NAME)

    assert value == ENV_VAR_VALUE


def test_aws_secrets_loader_fail_for_none_existing_secret():
    client = get_stubbed_boto_client_error()
    aws_secrets_loader = secrets.AWSSecretsLoader(client=client)

    with pytest.raises(secrets.CredentialNotFoundError):
        value = aws_secrets_loader.load("SOME_UNKNOWN_SECRET")


# ----------------------------------------------------------------------------
# Test CredentialLoaderFactory
# ----------------------------------------------------------------------------


def test_credential_loader_exists():
    cred = secrets.CredentialLoader()
    assert cred is not None


def test_credential_loader_is_callable():
    cred = secrets.CredentialLoader()
    assert callable(cred)


def test_credential_loader_pass_empty_loaders():
    loaders = []
    cred = secrets.CredentialLoader(loaders=loaders)

    assert cred.loaders == loaders


def test_credential_loader_pass_dummy_loader_as_dict():
    loaders = [
        {"name": "DummyLoader", "loader": DummyLoader, "args": (), "kwargs": {"raise_not_found": True},},
    ]
    cred = secrets.CredentialLoader(loaders=loaders)

    assert isinstance(cred.loaders[0], DummyLoader)
    assert cred.loaders[0].raise_not_found == True


def test_credential_loader_pass_dummy_loader_as_callable():
    loaders = [DummyLoader]
    cred = secrets.CredentialLoader(loaders=loaders)

    assert isinstance(cred.loaders[0], DummyLoader)
    assert cred.loaders[0].raise_not_found == False


def test_credential_loader_pass_dummy_loader_as_tuple():
    loaders = [
        ("DummyLoader", DummyLoader, (), {"raise_not_found": True}),
    ]
    cred = secrets.CredentialLoader(loaders=loaders)

    assert isinstance(cred.loaders[0], DummyLoader)
    assert cred.loaders[0].raise_not_found == True


def test_credential_loader_construct_loader_list():
    loaders = [
        ("DummyLoader", DummyLoader, (), {"raise_not_found": True}),
    ]
    cred = secrets.CredentialLoader(loaders=[])
    loader_list = cred._construct_loader_list(loaders)

    assert isinstance(loader_list[0], DummyLoader)
    assert loader_list[0].raise_not_found == True


def test_credential_loader_construct_loader_list_fail_for_wrong_type():
    loaders = [DummyLoader()]
    cred = secrets.CredentialLoader(loaders=[])

    with pytest.raises(secrets.ConstructLoaderError):
        loader_list = cred._construct_loader_list(loaders)


def test_credential_loader_construct_loader():
    loader_name = "DummyLoader"
    loader_class = DummyLoader
    kwargs = {"raise_not_found": True}

    cred = secrets.CredentialLoader(loaders=[])
    loader = cred._construct_loader(name=loader_name, loader=loader_class, **kwargs)

    assert isinstance(loader, DummyLoader)
    assert loader.raise_not_found == True


def test_credential_loader_with_dummy_loader():
    loaders = [DummyLoader]
    cred = secrets.CredentialLoader(loaders=loaders)
    dummy_credential = "some_cred"

    assert dummy_credential == cred(dummy_credential)


def test_credential_loader_empty_loaders_raises_no_loaders():
    loaders = []
    cred = secrets.CredentialLoader(loaders=loaders)

    with pytest.raises(secrets.NoLoaderConfiguredError):
        cred("SOME_DUMMY_CREDENTIAL")


def test_credential_loader_raises_not_found_after_last_loader_failed():
    loaders = [
        ("DummyLoader", DummyLoader, (), {"raise_not_found": True}),
    ]
    cred = secrets.CredentialLoader(loaders=loaders)
    credential_name = "SOME_DUMMY_CREDENTIAL"

    with pytest.raises(secrets.CredentialNotFoundError) as excption_info:
        cred(credential_name)

    assert f"Could not load '{credential_name}' using loaders: [" in str(excption_info.value)


# TODO: Review if this makes sense and if DFL should be tested for its structure
# NOTE: Review this test, delete DEFAULT_LOADERS if test is not added again
# def test_credential_loader_has_default_loaders():
#     cred = secrets.CredentialLoader()
#     assert secrets.DEFAULT_LOADERS == cred.loaders


def test_credential_laoder_register_loader():
    loaders = []
    cred = secrets.CredentialLoader(loaders=loaders)
    loader = DummyLoader
    cred.register(name="DummyLoader", loader=loader)

    assert isinstance(cred.loaders[0], DummyLoader)
    assert len(cred.loaders) == 1


def test_credential_laoder_register_loader_with_kwargs():
    loaders = []
    cred = secrets.CredentialLoader(loaders=loaders)
    loader = DummyLoader
    cred.register(name="DummyLoader", loader=loader, raise_not_found=True)

    assert isinstance(cred.loaders[0], DummyLoader)
    assert len(cred.loaders) == 1
    assert cred.loaders[0].raise_not_found == True


def test_credential_laoder_register_loader_order():
    default_loaders = [secrets.EnvLoader]
    cred = secrets.CredentialLoader(default_loaders)

    assert len(cred.loaders) == len(default_loaders)

    cred.register(name="dummy", loader=DummyLoader)

    assert len(cred.loaders) == len(default_loaders) + 1
    assert isinstance(cred.loaders[0], DummyLoader)


def test_credential():
    assert isinstance(secrets.credential, secrets.CredentialLoader)


# ----------------------------------------------------------------------------
# Test Credential
# ----------------------------------------------------------------------------
#
#
# def test_credential_exists():
#     name = "DUMMY_CREDENTIAL"
#     secret_value = "secret_key"
#     assert secrets.Credential(name=name, secret=secret_value)
#
#
# def test_credential_secret_is_not_displayed_in_str():
#     name = "DUMMY_CREDENTIAL"
#     secret_value = "secret_key"
#     cred = secrets.Credential(name=name, secret=secret_value)
#     assert name in str(cred)
#     assert secret_value not in str(cred)
#
#
# def test_credential_secret_is_not_displayed_when_called_directly():
#     name = "DUMMY_CREDENTIAL"
#     secret_value = "secret_key"
#     cred = secrets.Credential(name=name, secret=secret_value)
#     assert secret_value != cred.secret
#
#
# def test_credential_unpack():
#     name = "DUMMY_CREDENTIAL"
#     secret_value = "secret_key"
#     cred = secrets.Credential(name=name, secret=secret_value)
#     cred_dict = {**cred}
#     assert name in cred_dict
#     assert cred_dict[name] == secret_value
#
#
# def test_credential_reveal_secret():
#     name = "DUMMY_CREDENTIAL"
#     secret_value = "secret_key"
#     cred = secrets.Credential(name=name, secret=secret_value)
#     assert secret_value == cred.reveal()
#
#
# def test_credential_block_secret_reassign():
#     name = "DUMMY_CREDENTIAL"
#     secret_value = "secret_key"
#     cred = secrets.Credential(name=name, secret=secret_value)
#     second_secret_value = "second_secret"
#     with pytest.raises(AttributeError):
#         cred.secret = second_secret_value
#
#
# def test_credential_block_name_reassign():
#     name = "DUMMY_CREDENTIAL"
#     secret_value = "secret_key"
#     cred = secrets.Credential(name=name, secret=secret_value)
#     second_name = "NEW_NAME"
#     with pytest.raises(AttributeError):
#         cred.name = second_name
#
#
# def test_credential_str_name_only():
#     list_name = [
#         "DUMMY_CREDENTIAL",
#     ]
#     tuple_name = ("DUMMY_CREDENTIAL",)
#     int_name = 123
#     str_name = "DUMMY_CREDENTIAL"
#     secret_value = "secret_key"
#     with pytest.raises(secrets.CredentialMutabilityError):
#         cred = secrets.Credential(name=list_name, secret=secret_value)
#     with pytest.raises(secrets.CredentialMutabilityError):
#         cred = secrets.Credential(name=tuple_name, secret=secret_value)
#     with pytest.raises(secrets.CredentialMutabilityError):
#         cred = secrets.Credential(name=int_name, secret=secret_value)
#     assert secrets.Credential(name=str_name, secret=secret_value)
#
#
# def test_credential_str_int_secret_only():
#     name = "DUMMY_CREDENTIAL"
#     list_secret = [
#         "list_secret",
#     ]
#     dict_secret = {
#         "dict_key": "dict_secret",
#     }
#     tuple_secret = ("tuple_secret",)
#     int_secret = 123
#     str_secret = "str_secret"
#     with pytest.raises(secrets.CredentialMutabilityError):
#         cred = secrets.Credential(name=name, secret=list_secret)
#     with pytest.raises(secrets.CredentialMutabilityError):
#         cred = secrets.Credential(name=name, secret=dict_secret)
#     with pytest.raises(secrets.CredentialMutabilityError):
#         cred = secrets.Credential(name=name, secret=tuple_secret)
#
#     assert secrets.Credential(name=name, secret=int_secret)
#     assert secrets.Credential(name=name, secret=str_secret)
#
#
# def test_credential_len():
#     name = "DUMMY_CREDENTIAL"
#     secret_value = "secret_key"
#     cred = secrets.Credential(name=name, secret=secret_value)
#     assert len(cred) == 1
#
#
# def test_credential_getitem():
#     name = "DUMMY_CREDENTIAL"
#     secret_value = "secret_key"
#     cred = secrets.Credential(name=name, secret=secret_value)
#     assert cred[name] == secret_value
#
#
# def test_credential_iter():
#     name = "DUMMY_CREDENTIAL"
#     secret_value = "secret_key"
#     cred = secrets.Credential(name=name, secret=secret_value)
#     secret_list = [secret_name for secret_name in cred]
#     assert len(secret_list) == 1
#     assert name in secret_list
#
#
# ----------------------------------------------------------------------------
# Test Credentials
# ----------------------------------------------------------------------------
#
#
# def test_credentials_load_single_from_dict():
#     secret_name = "SecretName"
#     secret_value = "SecretValue"
#     secrets_dict = {
#         secret_name: secret_value,
#     }
#     creds = secrets.Credentials()
#     assert 1 == creds.load(secrets_dict)
#
#
# def test_credentials_load_multiple_from_dict():
#     secrets_dict = {
#         "SecretName": "SecretValue",
#         "SecondSecretName": "SecondSecretValue",
#     }
#     creds = secrets.Credentials()
#     assert 2 == creds.load(secrets_dict)
#
#
# def test_credentials_load_none_from_dict():
#     secrets_dict = {}
#     creds = secrets.Credentials()
#     assert 0 == creds.load(secrets_dict)
#
#
# def test_credentials_get_credential():
#     secret_name = "SecretName"
#     secret_value = "SecretValue"
#     secrets_dict = {
#         secret_name: secret_value,
#     }
#     creds = secrets.Credentials()
#     creds.load(secrets_dict)
#
#     assert creds.get(secret_name) == secret_value
#
#
# def test_credentials_len():
#     secrets_dict = {
#         "SecretName": "SecretValue",
#     }
#     creds_1 = secrets.Credentials()
#     creds_1.load(secrets_dict)
#     assert len(creds_1) == 1
#
#     secrets_dict["SecondSecretName"] = "SecondSecret"
#     creds_2 = secrets.Credentials()
#     creds_2.load(secrets_dict)
#     assert len(creds_2) == 2
#
#
# def test_credentials_getitem():
#     secret_name = "SecretName"
#     secret_value = "SecretValue"
#     secrets_dict = {secret_name: secret_value, "SecondSecretName": "SecondSecretValue"}
#     creds = secrets.Credentials()
#     creds.load(secrets_dict)
#
#     assert creds[secret_name] == secret_value
#
#
# def test_credentials_getitem_unknown_item():
#     secret_name = "SecretName"
#     secret_value = "SecretValue"
#     secrets_dict = {secret_name: secret_value, "SecondSecretName": "SecondSecretValue"}
#     creds = secrets.Credentials()
#     creds.load(secrets_dict)
#
#     with pytest.raises(KeyError):
#         creds["ThirdSecretName"]
#
#
# def test_credentials_iter():
#     secrets_dict = {
#         "SecretName": "SecretValue",
#         "SecondSecretName": "SecondSecretValue",
#     }
#
#     creds = secrets.Credentials()
#     creds.load(secrets_dict)
#
#     for secret_name in creds:
#         assert secret_name in secrets_dict.keys()
#
#
# def test_credentials_load_string_secret():
#     creds = secrets.Credentials()
#
#     with pytest.raises(NotImplementedError):
#         creds.load("SOME_STRING_SECRET")
#
#
# def test_credentials_load_list_secret():
#     creds = secrets.Credentials()
#
#     with pytest.raises(NotImplementedError):
#         creds.load(["SECRET_NAME_1", "SECRET_NAME_2"])
#
#
# def test_credentials_load_tuple_secret():
#     creds = secrets.Credentials()
#
#     with pytest.raises(NotImplementedError):
#         creds.load(("SECRET_NAME_1", "SECRET_NAME_2"))
#
#
# def test_credentials_load_none_as_secret_value():
#     creds = secrets.Credentials()
#     with pytest.raises(secrets.CredentialMutabilityError):
#         creds.load(
#             {"SECRET_NAME": None,}
#         )
#
#
# TODO:
#     - Reload behaviour
