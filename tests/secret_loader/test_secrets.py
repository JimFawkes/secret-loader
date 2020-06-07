"""
Copyright: (c) 2020, Moritz Eilfort
GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""

import pytest

from contextlib import contextmanager

import boto3
import base64

import datetime
import getpass

from secret_loader.secrets import LoaderContainer, SecretLoader, secret
from secret_loader.loaders import EnvLoader
from secret_loader.exceptions import (
    ConstructLoaderError,
    NoLoaderConfiguredError,
    SecretNotFoundError,
)

from . import helpers

# ----------------------------------------------------------------------------
# Test LoaderContainer
# ----------------------------------------------------------------------------


def test_loader_container_has_expected_structure():
    loader_obj = "dummy_loader"
    priority = 987
    loader_class = "dummy_class"
    args = ()
    kwargs = {}

    loader = LoaderContainer(
        loader=loader_obj, priority=priority, loader_class=loader_class, args=args, kwargs=kwargs
    )

    assert isinstance(loader, LoaderContainer)
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
        loader = LoaderContainer(loader=loader_obj,)

    with pytest.raises(TypeError):
        loader = LoaderContainer(loader=loader_obj, priority=priority,)


# ----------------------------------------------------------------------------
# Test SecretLoaderFactory
# ----------------------------------------------------------------------------


def test_secret_loader_is_callable():
    secret = SecretLoader()
    assert callable(secret)


def test_secret_loader_pass_empty_loaders():
    loaders = []
    secret = SecretLoader(loaders=loaders)

    assert secret.loaders == loaders


def test_secret_loader_pass_dummy_loader_as_dict():
    loaders = [
        {
            "loader": helpers.DummyLoader,
            "priority": 0,
            "args": (),
            "kwargs": {"raise_not_found": True},
        },
    ]
    secret = SecretLoader(loaders=loaders)

    assert isinstance(secret.loaders[0].loader, helpers.DummyLoader)
    assert secret.loaders[0].loader.raise_not_found == True


def test_secret_loader_pass_dummy_loader_as_callable():
    loaders = [helpers.DummyLoader]
    secret = SecretLoader(loaders=loaders)

    assert isinstance(secret.loaders[0].loader, helpers.DummyLoader)
    assert secret.loaders[0].loader.raise_not_found == False


def test_secret_loader_pass_dummy_loader_as_tuple():
    loaders = [
        (helpers.DummyLoader, 1, (), {"raise_not_found": True}),
    ]
    secret = SecretLoader(loaders=loaders)

    assert isinstance(secret.loaders[0].loader, helpers.DummyLoader)
    assert secret.loaders[0].loader.raise_not_found == True


# TODO: Verify/Modify/Refactor tests for construct_loader list/obj to expect
# the LoaderContainer type
def test_secret_loader_construct_loader_list():
    loaders = [
        (helpers.DummyLoader, 0, (), {"raise_not_found": True}),
    ]
    secret = SecretLoader(loaders=[])
    loader_list = secret._construct_loader_list(loaders)

    assert isinstance(loader_list[0].loader, helpers.DummyLoader)
    assert loader_list[0].loader.raise_not_found == True


def test_secret_loader_construct_loader_list_fail_for_wrong_type():
    loaders = [helpers.DummyLoader()]
    secret = SecretLoader(loaders=[])

    with pytest.raises(ConstructLoaderError):
        loader_list = secret._construct_loader_list(loaders)


def test_secret_loader_construct_loader_returns_loader_container_instance():
    loader_class = helpers.DummyLoader

    secret = SecretLoader(loaders=[])
    loader = secret._construct_loader(loader=loader_class)

    assert isinstance(loader, LoaderContainer)


def test_secret_loader_construct_loader_default_priority_is_zero():
    loader_class = helpers.DummyLoader

    secret = SecretLoader(loaders=[])
    loader = secret._construct_loader(loader=loader_class)

    assert loader.priority == 0


def test_secret_loader_construct_loader_set_priority():
    loader_class = helpers.DummyLoader

    secret = SecretLoader(loaders=[])
    loader = secret._construct_loader(loader=loader_class, priority=3)

    assert loader.priority == 3


def test_secret_loader_construct_loader_container_contains_expected_loader():
    loader_class = helpers.DummyLoader
    kwargs = {"raise_not_found": True}

    secret = SecretLoader(loaders=[])
    loader = secret._construct_loader(loader=loader_class, **kwargs)

    assert isinstance(loader.loader, helpers.DummyLoader)
    assert loader.loader.raise_not_found == True


def test_secret_loader_with_dummy_loader():
    loaders = [helpers.DummyLoader]
    secret = SecretLoader(loaders=loaders)
    dummy_secret = "some_secret"

    assert dummy_secret == secret(dummy_secret)


def test_secret_loader_empty_loaders_raises_no_loaders():
    loaders = []
    secret = SecretLoader(loaders=loaders)

    with pytest.raises(NoLoaderConfiguredError):
        secret("SOME_DUMMY_SECRET")


def test_secret_loader_raises_not_found_after_last_loader_failed():
    loaders = [
        (helpers.DummyLoader, 3, (), {"raise_not_found": True}),
    ]
    secret = SecretLoader(loaders=loaders)
    secret_name = "SOME_DUMMY_SECRET"

    with pytest.raises(SecretNotFoundError) as excption_info:
        secret(secret_name)

    assert f"Could not load '{secret_name}' using loaders: [" in str(excption_info.value)


def test_secret_laoder_register_loader():
    loaders = []
    secret = SecretLoader(loaders=loaders)
    loader = helpers.DummyLoader
    secret.register(loader=loader, priority=2)

    assert isinstance(secret.loaders[0].loader, helpers.DummyLoader)
    assert len(secret.loaders) == 1


def test_secret_laoder_priority_for_registered_loader():
    loaders = []
    priority = 3

    secret = SecretLoader(loaders=loaders)
    loader = helpers.DummyLoader
    secret.register(loader=loader, priority=priority)

    assert secret.loaders[0].priority == priority


def test_secret_laoder_register_loader_with_kwargs():
    loaders = []
    secret = SecretLoader(loaders=loaders)
    loader = helpers.DummyLoader
    secret.register(loader=loader, raise_not_found=True)

    assert isinstance(secret.loaders[0].loader, helpers.DummyLoader)
    assert len(secret.loaders) == 1
    assert secret.loaders[0].loader.raise_not_found == True


def test_secret_laoder_register_loader_order():
    default_loaders = [EnvLoader]
    secret = SecretLoader(default_loaders)

    assert len(secret.loaders) == len(default_loaders)

    secret.register(loader=helpers.DummyLoader, priority=1)

    assert len(secret.loaders) == len(default_loaders) + 1
    assert isinstance(secret.loaders[0].loader, helpers.DummyLoader)


def test_secret():
    assert isinstance(secret, SecretLoader)


def test_secret_loader_pass_parser():
    value = "secret_value"
    secret = SecretLoader(parser=lambda x: value)

    assert value == secret.parse(helpers.ENV_VAR_NAME)
    assert value == secret.parse(value)


def test_secret_loader_pass_parser_to_parse():
    value = "secret_value"
    parser = lambda x: value
    secret = SecretLoader()

    assert helpers.ENV_VAR_VALUE == secret.parse(helpers.ENV_VAR_VALUE)
    assert value == secret.parse(helpers.ENV_VAR_NAME, parser=parser)


def test_secret_loader_last_parser_beats_init_parser():
    value_1 = "secret_value_1"
    value_2 = "secret_value_2"
    parser_1 = lambda x: value_1
    parser_2 = lambda x: value_2
    secret = SecretLoader(parser=parser_1)

    assert value_1 == secret.parse(helpers.ENV_VAR_NAME)
    assert value_2 == secret.parse(helpers.ENV_VAR_NAME, parser=parser_2)


def test_secret_loader_parser_must_be_keyword():

    with pytest.raises(TypeError):
        secret = SecretLoader([(helpers.DummyLoader, 4, (), {}),], lambda x: x)


def test_secret_loader_use_parser_passed_to_call():
    secret = SecretLoader([(helpers.DummyLoader, 3, (), {}),])
    value = "secret_value"

    assert secret(helpers.ENV_VAR_NAME, parser=lambda x: value) == value


def test_secret_loader_parser_on_call_must_be_keyword():
    secret = SecretLoader([(helpers.DummyLoader, 3, (), {}),])
    value = "secret_value"

    with pytest.raises(TypeError):
        secret(helpers.ENV_VAR_NAME, lambda x: value)


def test_secret_loader_pass_kwargs_to_call():
    secret = SecretLoader([(helpers.DummyLoader, 3, (), {}),])

    assert (
        secret(helpers.ENV_VAR_NAME, some_dummy_var="abc", some_other_dummy="efg", some_int=1)
        == helpers.ENV_VAR_NAME
    )


def test_secret_loader_pass_loader_as_tuple_requires_four_elements():
    with pytest.raises(ConstructLoaderError):
        secret = SecretLoader([(helpers.DummyLoader,),])

    with pytest.raises(ConstructLoaderError):
        secret = SecretLoader([(helpers.DummyLoader, 0,),])

    with pytest.raises(ConstructLoaderError):
        secret = SecretLoader([(helpers.DummyLoader, 0, ()),])

    with pytest.raises(ConstructLoaderError):
        secret = SecretLoader([(helpers.DummyLoader, 0, (), {}, "other"),])

    secret = SecretLoader([(helpers.DummyLoader, 0, (), {}),])

    assert secret is not None


def test_secret_loader_highest_priority_loader_comes_first():
    high_priority = 3
    medium_priority = 2
    low_priority = 0
    secret = SecretLoader(
        [
            (helpers.DummyLoader, medium_priority, (), {}),
            (helpers.DummyLoader, low_priority, (), {}),
            (helpers.DummyLoader, high_priority, (), {}),
        ]
    )

    secret_2 = SecretLoader(
        [
            (helpers.DummyLoader, high_priority, (), {}),
            (helpers.DummyLoader, low_priority, (), {}),
            (helpers.DummyLoader, medium_priority, (), {}),
        ]
    )

    assert secret.loaders[0].priority == high_priority
    assert secret.loaders[-1].priority == low_priority

    assert secret_2.loaders[0].priority == high_priority
    assert secret_2.loaders[-1].priority == low_priority
