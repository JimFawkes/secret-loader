"""
Copyright: (c) 2020, Moritz Eilfort
GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
import getpass

import pytest

from secret_loader.loaders import EnvLoader, EnvFileLoader, AWSSecretsLoader, InputLoader
from secret_loader.exceptions import SecretNotFoundError

from . import helpers
from .helpers import sm_client_error, sm_client_response

# ----------------------------------------------------------------------------
# Test EnvLoader
# ----------------------------------------------------------------------------


def test_env_loader_load_env_variable(monkeypatch):
    monkeypatch.setenv(helpers.ENV_VAR_NAME, helpers.ENV_VAR_VALUE)

    env_loader = EnvLoader()
    value = env_loader.load(helpers.ENV_VAR_NAME)

    assert value == helpers.ENV_VAR_VALUE


def test_env_loader_fail_for_none_existing_variable():
    env_loader = EnvLoader()

    env_var_name = "MY_TEST_ENV_VAR"

    with pytest.raises(SecretNotFoundError):
        value = env_loader.load(env_var_name)


def test_env_loader_pass_kwargs(monkeypatch):
    monkeypatch.setenv(helpers.ENV_VAR_NAME, helpers.ENV_VAR_VALUE)

    env_loader = EnvLoader()
    value = env_loader.load(
        helpers.ENV_VAR_NAME, some_dummy_var="abc", some_other="efg", some_int=453
    )

    assert True


# ----------------------------------------------------------------------------
# Test EnvFileLoader
# ----------------------------------------------------------------------------


def test_env_file_loader_value_from_file(tmp_path):
    tmp_dir = tmp_path / "tmp_env"
    tmp_dir.mkdir()
    tmp_file = tmp_dir / ".env"
    tmp_file.write_text(helpers.ENV_FILE_CONTENT)

    env_file_loader = EnvFileLoader(file_path=tmp_file)
    value = env_file_loader.load(helpers.ENV_VAR_NAME)

    assert value == helpers.ENV_VAR_VALUE


def test_env_file_loader_fail_for_none_exisiting_variable(tmp_path):
    tmp_dir = tmp_path / "tmp_env"
    tmp_dir.mkdir()
    tmp_file = tmp_dir / ".env"
    tmp_file.write_text(helpers.ENV_FILE_CONTENT)

    env_file_loader = EnvFileLoader(file_path=tmp_file)
    with pytest.raises(SecretNotFoundError):
        value = env_file_loader.load("UNKNOWN_SECRET")


def test_env_file_loader_with_dummy_callables(monkeypatch):
    monkeypatch.setenv(helpers.ENV_VAR_NAME, helpers.ENV_VAR_VALUE)

    env_file_loader = EnvFileLoader(helpers.dummy_load_env_file, helpers.dummy_find_env_file)
    value = env_file_loader.load(helpers.ENV_VAR_NAME)

    assert value == helpers.ENV_VAR_VALUE


def test_env_file_loader_pass_kwargs(monkeypatch):
    variable = "SOME_VAR"
    monkeypatch.setenv(variable, variable)

    env_file_loader = EnvFileLoader(helpers.dummy_load_env_file, helpers.dummy_find_env_file)
    value = env_file_loader.load(
        variable, some_dummy_var="abc", some_other_dummy="efg", some_int=453,
    )

    assert True


# ----------------------------------------------------------------------------
# Test AWSSecretsManagerLoader
# ----------------------------------------------------------------------------

# NOTE: This is a very weak and strange test. I could not come up with a better
# solution for this. Please refactor ASAP.
def test_get_client():
    service_name = "secretsmanager"
    region_name = "eu-central-1"

    client = AWSSecretsLoader.get_client(service_name, region_name)
    client_type_str = str(client.__class__).lower()

    assert f"<class 'botocore.client.{service_name}'>" == client_type_str


def test_aws_secrets_loader_takes_client():

    client = helpers.get_stubbed_boto_client_response()
    aws_secrets_loader = AWSSecretsLoader(client=client)
    assert aws_secrets_loader.client is client


def test_aws_secrets_loader_get_secret_value(sm_client_response):
    client = sm_client_response
    aws_secrets_loader = AWSSecretsLoader(client=client)
    value = aws_secrets_loader.load(helpers.ENV_VAR_NAME)

    assert value == helpers.ENV_VAR_VALUE


def test_aws_secrets_loader_fail_for_none_existing_secret(sm_client_error):
    client = sm_client_error
    # client = get_stubbed_boto_client_error()
    aws_secrets_loader = AWSSecretsLoader(client=client)

    with pytest.raises(SecretNotFoundError):
        value = aws_secrets_loader.load("SOME_UNKNOWN_SECRET")


def test_aws_secrets_loader_pass_kwargs_to_load(sm_client_response):
    client = sm_client_response
    aws_secrets_loader = AWSSecretsLoader(client=client)
    value = aws_secrets_loader.load(
        helpers.ENV_VAR_NAME, some_dummy_var="abc", some_other_dummy="efg", some_int=23
    )

    assert value == helpers.ENV_VAR_VALUE


# ----------------------------------------------------------------------------
# Test InputLoader
# ----------------------------------------------------------------------------


def test_input_loader_fail_if_prompt_param_is_missing(monkeypatch):
    secret_value = "some_secret"

    input_loader = InputLoader()
    monkeypatch.setattr("getpass.getpass", lambda: secret_value)
    with pytest.raises(SecretNotFoundError):
        value = input_loader.load("SOME_SECRET_NAME")


def test_input_loader_prompt_for_input(monkeypatch):
    secret_name = "SOME_SECRET_NAME"
    secret_value = "some_secret"

    monkeypatch.setattr("getpass.getpass", lambda x: secret_value)
    input_loader = InputLoader(input=getpass.getpass)
    # monkeypatch.setattr(getpass, f"Enter Value for {secret_name}: ", lambda x: secret_value)
    value = input_loader.load(secret_name, prompt_input=True)

    assert value == secret_value


def test_input_loader_pass_kwargs_to_load(monkeypatch):
    secret_value = "some_secret"

    monkeypatch.setattr("getpass.getpass", lambda x: secret_value)

    input_loader = InputLoader(input=getpass.getpass)
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

    input_loader = InputLoader(input=input)
    # monkeypatch.setattr(getpass, f"Enter Value for {secret_name}: ", lambda x: secret_value)
    value = input_loader.load(secret_name, prompt_input=True)

    assert value == secret_value


def test_input_loader_pass_dummy_input_callable():
    secret_name = "SOME_SECRET_NAME"
    secret_value = "some_secret"

    input_loader = InputLoader(input=lambda x: secret_value)
    # monkeypatch.setattr(getpass, f"Enter Value for {secret_name}: ", lambda x: secret_value)
    value = input_loader.load(secret_name, prompt_input=True)

    assert value == secret_value
