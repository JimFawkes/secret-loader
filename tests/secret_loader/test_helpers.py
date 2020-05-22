"""
Copyright: (c) 2020, Moritz Eilfort
GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

This module tests all helper methods
"""

import pytest

from . import helpers
from .helpers import get_parse_args, valid_loader_class
from secret_loader.exceptions import SecretNotFoundError


def test_dummy_load_env_file():
    assert helpers.dummy_load_env_file("") is None


def test_dummy_find_env_file():
    assert helpers.dummy_find_env_file() is None


# NOTE: This is a very weak and strange test. I could not come up with a better
# solution for this. Please refactor ASAP.
def test_get_stubbed_boto_client_response():
    service_name = "secretsmanager"
    region_name = "eu-central-1"

    client = helpers.get_stubbed_boto_client_response(service_name, region_name)
    client_type_str = str(client.__class__).lower()
    assert f"<class 'botocore.client.{service_name}'>" == client_type_str


def test_get_stubbed_boto_client_error():
    service_name = "secretsmanager"
    region_name = "eu-central-1"

    client = helpers.get_stubbed_boto_client_error(service_name, region_name)
    client_type_str = str(client.__class__).lower()
    assert f"<class 'botocore.client.{service_name}'>" == client_type_str


# ----------------------------------------------------------------------------
# Test DumyLoader
# ----------------------------------------------------------------------------


def test_dummy_loader_load_variable():
    dummy_loader = helpers.DummyLoader()
    dummy_var_name = "MY_TEST_ENV_VAR"

    value = dummy_loader.load(dummy_var_name)

    assert value == dummy_var_name


def test_dummy_loader_fail_for_none():
    dummy_loader = helpers.DummyLoader()

    with pytest.raises(SecretNotFoundError):
        value = dummy_loader.load(None)


def test_dummy_loader_fail_if_forced():
    dummy_loader = helpers.DummyLoader(raise_not_found=True)

    with pytest.raises(SecretNotFoundError) as exception_info:
        value = dummy_loader.load("some_var")

    assert "raise_not_found" in str(exception_info.value)


def test_dummy_loader_pass_kwargs():
    dummy_loader = helpers.DummyLoader()
    dummy_var_name = "MY_TEST_ENV_VAR"

    value = dummy_loader.load(
        dummy_var_name, some_dummy_var="abc", some_other_dummy="efg", some_int=543
    )

    assert True


# ----------------------------------------------------------------------------
# Test CLI Helpers
# ----------------------------------------------------------------------------


def test_argument_parser_exits_for_missing_required_args(get_parse_args):
    with pytest.raises(SystemExit) as e:
        args = get_parse_args()

    assert e.value.code != 0


def test_argument_parser_takes_a_secret_name(get_parse_args):
    secret_name = "SOME_NAME"
    args = get_parse_args(["--name", f"{secret_name}"])

    assert args.name == secret_name


def test_argument_parser_sets_arg_fail_as_false_by_default(get_parse_args):
    secret_name = "SOME_NAME"
    args = get_parse_args(["--name", f"{secret_name}"])

    assert args.fail is False


def test_argument_parser_sets_arg_fail_as_true_when_provided(get_parse_args):
    secret_name = "SOME_NAME"
    args = get_parse_args(["--name", f"{secret_name}", "--fail"])

    assert args.fail is True


def test_argument_parser_sets_arg_loader_as_none_by_default(get_parse_args):
    secret_name = "SOME_NAME"
    args = get_parse_args(["--name", f"{secret_name}"])

    assert args.loader is None


def test_argument_parser_exits_for_unknown_loader(get_parse_args):
    secret_name = "SOME_NAME"
    unknown_loader = "no_real_loader"

    with pytest.raises(SystemExit) as e:
        get_parse_args(["--name", secret_name, "--loader", unknown_loader])

    assert e.value.code != 0


def test_argument_parser_accepts_valid_loader(get_parse_args, valid_loader_class):
    secret_name = "SOME_NAME"

    args = get_parse_args(["--name", secret_name, "--loader", valid_loader_class])

    assert args.loader == valid_loader_class


def test_argument_parser_takes_a_custom_loader(get_parse_args):
    secret_name = "SOME_NAME"
    custom_loader = "some_module.CustomLoader"
    args = get_parse_args(["--name", secret_name, "--custom_loader", custom_loader])

    assert args.custom_loader == custom_loader


def test_argument_parser_takes_a_custom_loader_and_priority(get_parse_args):
    secret_name = "SOME_NAME"
    custom_loader = "some_module.CustomLoader"
    priority = 10
    args = get_parse_args(
        ["--name", secret_name, "--custom_loader", custom_loader, "--priority", str(priority)]
    )

    assert args.custom_loader == custom_loader
    assert args.priority == float(priority)


def test_argument_parser_fails_for_wrong_priority_format(get_parse_args):
    secret_name = "SOME_NAME"
    custom_loader = "some_module.CustomLoader"
    priority = "broken_priority"

    with pytest.raises(SystemExit) as e:
        args = get_parse_args(
            ["--name", secret_name, "--custom_loader", custom_loader, "--priority", priority]
        )

    assert e.value.code != 0


def test_argument_parser_exits_with_code_zero_when_missing_name_arg_but_list_loader_arg_given(
    get_parse_args,
):
    with pytest.raises(SystemExit) as e:
        args = get_parse_args(["--list_loaders"])

    assert 0 == e.value.code


def test_argument_parser_exits_with_code_zero_when_list_loader_arg_given(get_parse_args,):
    with pytest.raises(SystemExit) as e:
        args = get_parse_args(["--name", "some_name", "--list_loaders"])

    assert 0 == e.value.code


def test_argument_parser_fails_for_remove_loader_arg_without_new_specified_loader(get_parse_args,):
    with pytest.raises(SystemExit) as e:
        args = get_parse_args(["--name", "some_name", "--remove_loaders"])

    assert 0 != e.value.code


def test_argument_parser_takes_remove_loader_for_specified_custom_loader(get_parse_args,):
    custom_loader = "some_module.CustomLoader"

    args = get_parse_args(
        ["--name", "some_name", "--custom_loader", custom_loader, "--remove_loaders"]
    )

    assert args.remove_loaders
    assert args.custom_loader == custom_loader


def test_argument_parser_takes_remove_loader_for_specified_loader(
    get_parse_args, valid_loader_class
):

    args = get_parse_args(
        ["--name", "some_name", "--loader", valid_loader_class, "--remove_loaders"]
    )

    assert args.remove_loaders
    assert args.loader == valid_loader_class


def test_argument_parser_fails_if_both_custom_loader_and_loader_are_specified(
    get_parse_args, valid_loader_class
):

    with pytest.raises(SystemExit) as e:
        args = get_parse_args(
            [
                "--name",
                "some_name",
                "--loader",
                valid_loader_class,
                "--custom_loader",
                "some_custom_loader",
            ]
        )

    assert e.value.code != 0
