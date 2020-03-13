import pytest

from contextlib import contextmanager

import boto3
import base64

import botocore.session
from botocore.stub import Stubber, ANY
import datetime
import getpass

from secret_loader import secrets


# TODO: Move the appropriate things to a base file
# TODO: Refacotr tests
# TODO: Use fixtures
# TODO: Use parameterized fixtures to not repeat so much
# TODO: Add docstrings

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
    ]
)
def sm_client_error(request):
    return get_stubbed_boto_client_error(service_error_code=request.param)


@pytest.fixture(params=[SM_RESPONSE_TEMPLATE, SM_BINARY_RESPONSE_TEMPLATE])
def sm_client_response(request):
    return get_stubbed_boto_client_response(response=request.param)


def dummy_load_env_file(filepath, *args, **kwargs):
    return None


def test_dummy_load_env_file():
    assert dummy_load_env_file("") is None


def dummy_find_env_file(*args, **kwargs):
    return None


def test_dummy_find_env_file():
    assert dummy_find_env_file() is None


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


def test_base_loader_pass_kwargs():
    base_loader = secrets.BaseLoader()

    with pytest.raises(NotImplementedError):
        base_loader.load("SOME_VAR", some_dummy_var="abc", some_other_var="abc", some_int=43)


# ----------------------------------------------------------------------------
# Test DumyLoader
# ----------------------------------------------------------------------------


class DummyLoader(secrets.BaseLoader):
    def __init__(self, raise_not_found=False):
        self.raise_not_found = raise_not_found

    def load(self, secret_name, **kwargs):

        if self.raise_not_found:
            raise secrets.SecretNotFoundError(f"DummyLoader raise_not_found=True")

        if secret_name is None:
            raise secrets.SecretNotFoundError(f"DummyLoader encountered a None Value")

        return secret_name


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

    with pytest.raises(secrets.SecretNotFoundError):
        value = dummy_loader.load(None)


def test_dummy_loader_fail_if_forced():
    dummy_loader = DummyLoader(raise_not_found=True)

    with pytest.raises(secrets.SecretNotFoundError) as exception_info:
        value = dummy_loader.load("some_var")

    assert "raise_not_found" in str(exception_info.value)


def test_dummy_loader_pass_kwargs():
    dummy_loader = DummyLoader()
    dummy_var_name = "MY_TEST_ENV_VAR"

    value = dummy_loader.load(
        dummy_var_name, some_dummy_var="abc", some_other_dummy="efg", some_int=543
    )

    assert True


# ----------------------------------------------------------------------------
# Test EnvLoader
# ----------------------------------------------------------------------------


def test_env_loader_exists():
    env_loader = secrets.EnvLoader()

    assert env_loader is not None
    assert isinstance(env_loader, secrets.EnvLoader)


def test_env_loader_load_env_variable(monkeypatch):
    monkeypatch.setenv(ENV_VAR_NAME, ENV_VAR_VALUE)

    env_loader = secrets.EnvLoader()
    value = env_loader.load(ENV_VAR_NAME)

    assert value == ENV_VAR_VALUE


def test_env_loader_fail_for_none_existing_variable():
    env_loader = secrets.EnvLoader()

    env_var_name = "MY_TEST_ENV_VAR"

    with pytest.raises(secrets.SecretNotFoundError):
        value = env_loader.load(env_var_name)


def test_env_loader_pass_kwargs(monkeypatch):
    monkeypatch.setenv(ENV_VAR_NAME, ENV_VAR_VALUE)

    env_loader = secrets.EnvLoader()
    value = env_loader.load(ENV_VAR_NAME, some_dummy_var="abc", some_other="efg", some_int=453)

    assert True


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
    with pytest.raises(secrets.SecretNotFoundError):
        value = env_file_loader.load("UNKNOWN_SECRET")


def test_env_file_loader_with_dummy_callables(monkeypatch):
    monkeypatch.setenv(ENV_VAR_NAME, ENV_VAR_VALUE)

    env_file_loader = secrets.EnvFileLoader(dummy_load_env_file, dummy_find_env_file)
    value = env_file_loader.load(ENV_VAR_NAME)

    assert value == ENV_VAR_VALUE


def test_env_file_loader_pass_kwargs(monkeypatch):
    variable = "SOME_VAR"
    monkeypatch.setenv(variable, variable)

    env_file_loader = secrets.EnvFileLoader(dummy_load_env_file, dummy_find_env_file)
    value = env_file_loader.load(
        variable, some_dummy_var="abc", some_other_dummy="efg", some_int=453,
    )

    assert True


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


def test_aws_secrets_loader_get_secret_value(sm_client_response):
    client = sm_client_response
    aws_secrets_loader = secrets.AWSSecretsLoader(client=client)
    value = aws_secrets_loader.load(ENV_VAR_NAME)

    assert value == ENV_VAR_VALUE


def test_aws_secrets_loader_fail_for_none_existing_secret(sm_client_error):
    client = sm_client_error
    # client = get_stubbed_boto_client_error()
    aws_secrets_loader = secrets.AWSSecretsLoader(client=client)

    with pytest.raises(secrets.SecretNotFoundError):
        value = aws_secrets_loader.load("SOME_UNKNOWN_SECRET")


def test_aws_secrets_loader_pass_kwargs_to_load(sm_client_response):
    client = sm_client_response
    aws_secrets_loader = secrets.AWSSecretsLoader(client=client)
    value = aws_secrets_loader.load(
        ENV_VAR_NAME, some_dummy_var="abc", some_other_dummy="efg", some_int=23
    )

    assert True


# ----------------------------------------------------------------------------
# Test InputLoader
# ----------------------------------------------------------------------------


def test_input_loader_exits():
    input_loader = secrets.InputLoader()
    assert input_loader is not None


def test_input_loader_fail_if_prompt_param_is_missing(monkeypatch):
    secret_value = "some_secret"

    input_loader = secrets.InputLoader()
    monkeypatch.setattr("getpass.getpass", lambda: secret_value)
    with pytest.raises(secrets.SecretNotFoundError):
        value = input_loader.load("SOME_SECRET_NAME")


def test_input_loader_prompt_for_input(monkeypatch):
    secret_name = "SOME_SECRET_NAME"
    secret_value = "some_secret"

    monkeypatch.setattr("getpass.getpass", lambda x: secret_value)
    input_loader = secrets.InputLoader(input=getpass.getpass)
    # monkeypatch.setattr(getpass, f"Enter Value for {secret_name}: ", lambda x: secret_value)
    value = input_loader.load(secret_name, prompt_input=True)

    assert value == secret_value


def test_input_loader_pass_kwargs_to_load(monkeypatch):
    secret_value = "some_secret"

    monkeypatch.setattr("getpass.getpass", lambda x: secret_value)

    input_loader = secrets.InputLoader(input=getpass.getpass)
    value = input_loader.load(
        "SOME_SECRET_NAME",
        prompt_input=True,
        some_dummy_var="abc",
        some_other_var="efg",
        some_int=546,
    )

    assert value == secret_value


def test_input_loader_use_builtin_input_over_getpass(monkeypatch):
    secret_name = "SOME_SECRET_NAME"
    secret_value = "some_secret"
    monkeypatch.setattr("builtins.input", lambda x: secret_value)

    input_loader = secrets.InputLoader(input=input)
    # monkeypatch.setattr(getpass, f"Enter Value for {secret_name}: ", lambda x: secret_value)
    value = input_loader.load(secret_name, prompt_input=True)

    assert value == secret_value


def test_input_loader_pass_dummy_input_callable():
    secret_name = "SOME_SECRET_NAME"
    secret_value = "some_secret"

    input_loader = secrets.InputLoader(input=lambda x: secret_value)
    # monkeypatch.setattr(getpass, f"Enter Value for {secret_name}: ", lambda x: secret_value)
    value = input_loader.load(secret_name, prompt_input=True)

    assert value == secret_value


# ----------------------------------------------------------------------------
# Test LoaderContainer
# ----------------------------------------------------------------------------


def test_loader_container_exists():
    loader_obj = "dummy_loader"
    priority = 987
    loader_class = "dummy_class"
    args = ()
    kwargs = {}

    loader = secrets.LoaderContainer(
        loader=loader_obj, priority=priority, loader_class=loader_class, args=args, kwargs=kwargs
    )

    assert isinstance(loader, secrets.LoaderContainer)
    assert loader.loader == loader_obj
    assert loader.priority == priority
    assert loader.loader_class == loader_class


def test_loader_container_fails_for_missing_field():
    loader_obj = "dummy_loader"
    priority = 987
    loader_class = "dummy_class"
    args = ()
    kwargs = {}

    with pytest.raises(TypeError):
        loader = secrets.LoaderContainer(loader=loader_obj,)

    with pytest.raises(TypeError):
        loader = secrets.LoaderContainer(loader=loader_obj, priority=priority,)


# ----------------------------------------------------------------------------
# Test SecretLoaderFactory
# ----------------------------------------------------------------------------


def test_secret_loader_exists():
    secret = secrets.SecretLoader()
    assert secret is not None


def test_secret_loader_is_callable():
    secret = secrets.SecretLoader()
    assert callable(secret)


def test_secret_loader_pass_empty_loaders():
    loaders = []
    secret = secrets.SecretLoader(loaders=loaders)

    assert secret.loaders == loaders


def test_secret_loader_pass_dummy_loader_as_dict():
    loaders = [
        {"loader": DummyLoader, "priority": 0, "args": (), "kwargs": {"raise_not_found": True},},
    ]
    secret = secrets.SecretLoader(loaders=loaders)

    assert isinstance(secret.loaders[0].loader, DummyLoader)
    assert secret.loaders[0].loader.raise_not_found == True


def test_secret_loader_pass_dummy_loader_as_callable():
    loaders = [DummyLoader]
    secret = secrets.SecretLoader(loaders=loaders)

    assert isinstance(secret.loaders[0].loader, DummyLoader)
    assert secret.loaders[0].loader.raise_not_found == False


def test_secret_loader_pass_dummy_loader_as_tuple():
    loaders = [
        (DummyLoader, 1, (), {"raise_not_found": True}),
    ]
    secret = secrets.SecretLoader(loaders=loaders)

    assert isinstance(secret.loaders[0].loader, DummyLoader)
    assert secret.loaders[0].loader.raise_not_found == True


# TODO: Verify/Modify/Refactor tests for construct_loader list/obj to expect
# the LoaderContainer type
def test_secret_loader_construct_loader_list():
    loaders = [
        (DummyLoader, 0, (), {"raise_not_found": True}),
    ]
    secret = secrets.SecretLoader(loaders=[])
    loader_list = secret._construct_loader_list(loaders)

    assert isinstance(loader_list[0].loader, DummyLoader)
    assert loader_list[0].loader.raise_not_found == True


def test_secret_loader_construct_loader_list_fail_for_wrong_type():
    loaders = [DummyLoader()]
    secret = secrets.SecretLoader(loaders=[])

    with pytest.raises(secrets.ConstructLoaderError):
        loader_list = secret._construct_loader_list(loaders)


def test_secret_loader_construct_loader_returns_loader_container_instance():
    loader_class = DummyLoader

    secret = secrets.SecretLoader(loaders=[])
    loader = secret._construct_loader(loader=loader_class)

    assert isinstance(loader, secrets.LoaderContainer)


def test_secret_loader_construct_loader_default_priority_is_zero():
    loader_class = DummyLoader

    secret = secrets.SecretLoader(loaders=[])
    loader = secret._construct_loader(loader=loader_class)

    assert loader.priority == 0


def test_secret_loader_construct_loader_set_priority():
    loader_class = DummyLoader

    secret = secrets.SecretLoader(loaders=[])
    loader = secret._construct_loader(loader=loader_class, priority=3)

    assert loader.priority == 3


def test_secret_loader_construct_loader_container_contains_expected_loader():
    loader_class = DummyLoader
    kwargs = {"raise_not_found": True}

    secret = secrets.SecretLoader(loaders=[])
    loader = secret._construct_loader(loader=loader_class, **kwargs)

    assert isinstance(loader.loader, DummyLoader)
    assert loader.loader.raise_not_found == True


def test_secret_loader_with_dummy_loader():
    loaders = [DummyLoader]
    secret = secrets.SecretLoader(loaders=loaders)
    dummy_secret = "some_secret"

    assert dummy_secret == secret(dummy_secret)


def test_secret_loader_empty_loaders_raises_no_loaders():
    loaders = []
    secret = secrets.SecretLoader(loaders=loaders)

    with pytest.raises(secrets.NoLoaderConfiguredError):
        secret("SOME_DUMMY_SECRET")


def test_secret_loader_raises_not_found_after_last_loader_failed():
    loaders = [
        (DummyLoader, 3, (), {"raise_not_found": True}),
    ]
    secret = secrets.SecretLoader(loaders=loaders)
    secret_name = "SOME_DUMMY_SECRET"

    with pytest.raises(secrets.SecretNotFoundError) as excption_info:
        secret(secret_name)

    assert f"Could not load '{secret_name}' using loaders: [" in str(excption_info.value)


def test_secret_laoder_register_loader():
    loaders = []
    secret = secrets.SecretLoader(loaders=loaders)
    loader = DummyLoader
    secret.register(loader=loader, priority=2)

    assert isinstance(secret.loaders[0].loader, DummyLoader)
    assert len(secret.loaders) == 1


def test_secret_laoder_priority_for_registered_loader():
    loaders = []
    priority = 3

    secret = secrets.SecretLoader(loaders=loaders)
    loader = DummyLoader
    secret.register(loader=loader, priority=priority)

    assert secret.loaders[0].priority == priority


def test_secret_laoder_register_loader_with_kwargs():
    loaders = []
    secret = secrets.SecretLoader(loaders=loaders)
    loader = DummyLoader
    secret.register(loader=loader, raise_not_found=True)

    assert isinstance(secret.loaders[0].loader, DummyLoader)
    assert len(secret.loaders) == 1
    assert secret.loaders[0].loader.raise_not_found == True


def test_secret_laoder_register_loader_order():
    default_loaders = [secrets.EnvLoader]
    secret = secrets.SecretLoader(default_loaders)

    assert len(secret.loaders) == len(default_loaders)

    secret.register(loader=DummyLoader, priority=1)

    assert len(secret.loaders) == len(default_loaders) + 1
    assert isinstance(secret.loaders[0].loader, DummyLoader)


def test_secret():
    assert isinstance(secrets.secret, secrets.SecretLoader)


def test_secret_loader_pass_parser():
    value = "secret_value"
    secret = secrets.SecretLoader(parser=lambda x: value)

    assert value == secret.parse(ENV_VAR_NAME)
    assert value == secret.parse(value)


def test_secret_loader_pass_parser_to_parse():
    value = "secret_value"
    parser = lambda x: value
    secret = secrets.SecretLoader()

    assert ENV_VAR_VALUE == secret.parse(ENV_VAR_VALUE)
    assert value == secret.parse(ENV_VAR_NAME, parser=parser)


def test_secret_loader_last_parser_beats_init_parser():
    value_1 = "secret_value_1"
    value_2 = "secret_value_2"
    parser_1 = lambda x: value_1
    parser_2 = lambda x: value_2
    secret = secrets.SecretLoader(parser=parser_1)

    assert value_1 == secret.parse(ENV_VAR_NAME)
    assert value_2 == secret.parse(ENV_VAR_NAME, parser=parser_2)


def test_secret_loader_parser_must_be_keyword():

    with pytest.raises(TypeError):
        secret = secrets.SecretLoader([(DummyLoader, 4, (), {}),], lambda x: x)


def test_secret_loader_use_parser_passed_to_call():
    secret = secrets.SecretLoader([(DummyLoader, 3, (), {}),])
    value = "secret_value"

    assert secret(ENV_VAR_NAME, parser=lambda x: value) == value


def test_secret_loader_parser_on_call_must_be_keyword():
    secret = secrets.SecretLoader([(DummyLoader, 3, (), {}),])
    value = "secret_value"

    with pytest.raises(TypeError):
        secret(ENV_VAR_NAME, lambda x: value)


def test_secret_loader_pass_kwargs_to_call():
    secret = secrets.SecretLoader([(DummyLoader, 3, (), {}),])

    assert (
        secret(ENV_VAR_NAME, some_dummy_var="abc", some_other_dummy="efg", some_int=1)
        == ENV_VAR_NAME
    )


def test_secret_loader_pass_loader_as_tuple_requires_four_elements():
    with pytest.raises(secrets.ConstructLoaderError):
        secret = secrets.SecretLoader([(DummyLoader,),])

    with pytest.raises(secrets.ConstructLoaderError):
        secret = secrets.SecretLoader([(DummyLoader, 0,),])

    with pytest.raises(secrets.ConstructLoaderError):
        secret = secrets.SecretLoader([(DummyLoader, 0, ()),])

    with pytest.raises(secrets.ConstructLoaderError):
        secret = secrets.SecretLoader([(DummyLoader, 0, (), {}, "other"),])

    secret = secrets.SecretLoader([(DummyLoader, 0, (), {}),])

    assert secret is not None


def test_secret_loader_highest_priority_loader_comes_first():
    high_priority = 3
    medium_priority = 2
    low_priority = 0
    secret = secrets.SecretLoader(
        [
            (DummyLoader, medium_priority, (), {}),
            (DummyLoader, low_priority, (), {}),
            (DummyLoader, high_priority, (), {}),
        ]
    )

    secret_2 = secrets.SecretLoader(
        [
            (DummyLoader, high_priority, (), {}),
            (DummyLoader, low_priority, (), {}),
            (DummyLoader, medium_priority, (), {}),
        ]
    )

    assert secret.loaders[0].priority == high_priority
    assert secret.loaders[-1].priority == low_priority

    assert secret_2.loaders[0].priority == high_priority
    assert secret_2.loaders[-1].priority == low_priority
