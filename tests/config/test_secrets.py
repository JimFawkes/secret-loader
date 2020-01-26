import pytest
import os

from utils.config import secrets


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


# ----------------------------------------------------------------------------
# Test AWSSecretsManagerLoader
# ----------------------------------------------------------------------------


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
    cred = secrets.CredentialLoader()

    assert len(cred.loaders) == len(secrets.DEFAULT_LOADERS)

    cred.register(name="dummy", loader=DummyLoader)

    assert len(cred.loaders) == len(secrets.DEFAULT_LOADERS) + 1
    assert isinstance(cred.loaders[0], DummyLoader)


# ----------------------------------------------------------------------------
# Test Credential
# ----------------------------------------------------------------------------


def test_credential_exists():
    name = "DUMMY_CREDENTIAL"
    secret_value = "secret_key"
    assert secrets.Credential(name=name, secret=secret_value)


def test_credential_secret_is_not_displayed_in_str():
    name = "DUMMY_CREDENTIAL"
    secret_value = "secret_key"
    cred = secrets.Credential(name=name, secret=secret_value)
    assert name in str(cred)
    assert secret_value not in str(cred)


def test_credential_secret_is_not_displayed_when_called_directly():
    name = "DUMMY_CREDENTIAL"
    secret_value = "secret_key"
    cred = secrets.Credential(name=name, secret=secret_value)
    assert secret_value != cred.secret


def test_credential_unpack():
    name = "DUMMY_CREDENTIAL"
    secret_value = "secret_key"
    cred = secrets.Credential(name=name, secret=secret_value)
    cred_dict = {**cred}
    assert name in cred_dict
    assert cred_dict[name] == secret_value


def test_credential_reveal_secret():
    name = "DUMMY_CREDENTIAL"
    secret_value = "secret_key"
    cred = secrets.Credential(name=name, secret=secret_value)
    assert secret_value == cred.reveal()


def test_credential_block_secret_reassign():
    name = "DUMMY_CREDENTIAL"
    secret_value = "secret_key"
    cred = secrets.Credential(name=name, secret=secret_value)
    second_secret_value = "second_secret"
    with pytest.raises(AttributeError):
        cred.secret = second_secret_value


def test_credential_block_name_reassign():
    name = "DUMMY_CREDENTIAL"
    secret_value = "secret_key"
    cred = secrets.Credential(name=name, secret=secret_value)
    second_name = "NEW_NAME"
    with pytest.raises(AttributeError):
        cred.name = second_name


def test_credential_str_name_only():
    list_name = [
        "DUMMY_CREDENTIAL",
    ]
    tuple_name = ("DUMMY_CREDENTIAL",)
    int_name = 123
    str_name = "DUMMY_CREDENTIAL"
    secret_value = "secret_key"
    with pytest.raises(secrets.CredentialMutabilityError):
        cred = secrets.Credential(name=list_name, secret=secret_value)
    with pytest.raises(secrets.CredentialMutabilityError):
        cred = secrets.Credential(name=tuple_name, secret=secret_value)
    with pytest.raises(secrets.CredentialMutabilityError):
        cred = secrets.Credential(name=int_name, secret=secret_value)
    assert secrets.Credential(name=str_name, secret=secret_value)


def test_credential_str_int_secret_only():
    name = "DUMMY_CREDENTIAL"
    list_secret = [
        "list_secret",
    ]
    dict_secret = {
        "dict_key": "dict_secret",
    }
    tuple_secret = ("tuple_secret",)
    int_secret = 123
    str_secret = "str_secret"
    with pytest.raises(secrets.CredentialMutabilityError):
        cred = secrets.Credential(name=name, secret=list_secret)
    with pytest.raises(secrets.CredentialMutabilityError):
        cred = secrets.Credential(name=name, secret=dict_secret)
    with pytest.raises(secrets.CredentialMutabilityError):
        cred = secrets.Credential(name=name, secret=tuple_secret)

    assert secrets.Credential(name=name, secret=int_secret)
    assert secrets.Credential(name=name, secret=str_secret)


def test_credential_len():
    name = "DUMMY_CREDENTIAL"
    secret_value = "secret_key"
    cred = secrets.Credential(name=name, secret=secret_value)
    assert len(cred) == 1


def test_credential_getitem():
    name = "DUMMY_CREDENTIAL"
    secret_value = "secret_key"
    cred = secrets.Credential(name=name, secret=secret_value)
    assert cred[name] == secret_value


def test_credential_iter():
    name = "DUMMY_CREDENTIAL"
    secret_value = "secret_key"
    cred = secrets.Credential(name=name, secret=secret_value)
    secret_list = [secret_name for secret_name in cred]
    assert len(secret_list) == 1
    assert name in secret_list


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
