import pytest

from utils.config import secrets


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


def test_credentials_load_single_from_dict():
    secret_name = "SecretName"
    secret_value = "SecretValue"
    secrets_dict = {
        secret_name: secret_value,
    }
    creds = secrets.Credentials()
    assert 1 == creds.load(secrets_dict)


def test_credentials_load_multiple_from_dict():
    secrets_dict = {
        "SecretName": "SecretValue",
        "SecondSecretName": "SecondSecretValue",
    }
    creds = secrets.Credentials()
    assert 2 == creds.load(secrets_dict)


def test_credentials_load_none_from_dict():
    secrets_dict = {}
    creds = secrets.Credentials()
    assert 0 == creds.load(secrets_dict)


def test_credentials_get_credential():
    secret_name = "SecretName"
    secret_value = "SecretValue"
    secrets_dict = {
        secret_name: secret_value,
    }
    creds = secrets.Credentials()
    creds.load(secrets_dict)

    assert creds.get(secret_name) == secret_value


def test_credentials_len():
    secrets_dict = {
        "SecretName": "SecretValue",
    }
    creds_1 = secrets.Credentials()
    creds_1.load(secrets_dict)
    assert len(creds_1) == 1

    secrets_dict["SecondSecretName"] = "SecondSecret"
    creds_2 = secrets.Credentials()
    creds_2.load(secrets_dict)
    assert len(creds_2) == 2


def test_credentials_getitem():
    secret_name = "SecretName"
    secret_value = "SecretValue"
    secrets_dict = {secret_name: secret_value, "SecondSecretName": "SecondSecretValue"}
    creds = secrets.Credentials()
    creds.load(secrets_dict)

    assert creds[secret_name] == secret_value


def test_credentials_getitem_unknown_item():
    secret_name = "SecretName"
    secret_value = "SecretValue"
    secrets_dict = {secret_name: secret_value, "SecondSecretName": "SecondSecretValue"}
    creds = secrets.Credentials()
    creds.load(secrets_dict)

    with pytest.raises(KeyError):
        creds["ThirdSecretName"]


def test_credentials_iter():
    secrets_dict = {
        "SecretName": "SecretValue",
        "SecondSecretName": "SecondSecretValue",
    }

    creds = secrets.Credentials()
    creds.load(secrets_dict)

    for secret_name in creds:
        assert secret_name in secrets_dict.keys()


def test_credentials_load_string_secret():
    creds = secrets.Credentials()

    with pytest.raises(NotImplementedError):
        creds.load("SOME_STRING_SECRET")


def test_credentials_load_list_secret():
    creds = secrets.Credentials()

    with pytest.raises(NotImplementedError):
        creds.load(["SECRET_NAME_1", "SECRET_NAME_2"])


def test_credentials_load_tuple_secret():
    creds = secrets.Credentials()

    with pytest.raises(NotImplementedError):
        creds.load(("SECRET_NAME_1", "SECRET_NAME_2"))


def test_credentials_load_none_as_secret_value():
    creds = secrets.Credentials()
    with pytest.raises(secrets.CredentialMutabilityError):
        creds.load(
            {"SECRET_NAME": None,}
        )


# TODO:
#     - Reload behaviour
