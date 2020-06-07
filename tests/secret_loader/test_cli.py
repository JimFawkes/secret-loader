"""
Copyright: (c) 2020, Moritz Eilfort
GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""

import importlib
import pytest
from unittest.mock import patch

from secret_loader import cli

from . import helpers
from .helpers import get_parse_args, valid_loader, valid_loader_class

from secret_loader.exceptions import SecretNotFoundError
from secret_loader.secrets import LoaderContainer, SecretLoader


def test_secret_loader_cli(capsys):
    secret_name = "secret_name"
    secret_value = "secret_value"

    args = helpers.MockArgs(secret_name, secret=lambda x: secret_value)
    cli.secret_loader_cli(args)

    captured = capsys.readouterr()
    cleaned_output = captured.out.replace("\n", "")

    assert cleaned_output == secret_value


def test_secret_loader_cli_fail_silently(capsys):
    secret_name = "secret_name"

    def raise_on_call(val):
        raise SecretNotFoundError()

    args = helpers.MockArgs(secret_name, secret=raise_on_call)

    cli.secret_loader_cli(args)

    captured = capsys.readouterr()
    cleaned_output = captured.out.replace("\n", "")

    assert cleaned_output == ""


def test_secret_loader_cli_fail():
    secret_name = "secret_name"

    def raise_on_call(val):
        raise SecretNotFoundError()

    args = helpers.MockArgs(secret_name, fail=True, secret=raise_on_call)

    with pytest.raises(SecretNotFoundError):
        cli.secret_loader_cli(args)


@patch("secret_loader.cli.secret_loader_cli")
@patch("secret_loader.cli.parse_args")
def test_cli_function(mock_secret_loader_cli, mock_parse_args):
    cli.cli(parser=lambda: None)

    assert mock_secret_loader_cli.called
    assert mock_parse_args.called


def test_available_loader_count():
    assert 2 < len(cli.available_loaders)


def test_get_secret_loader_for_specific_loader(valid_loader, valid_loader_class):
    args = helpers.MockArgs("some_name", loader=valid_loader_class)

    with patch.object(SecretLoader, "register", return_value=None) as mock_register:
        secret = cli.get_secret_loader(args)

    assert mock_register.called
    mock_register.assert_called_once_with(valid_loader, cli.DEFAULT_PRIORITY)


def test_get_secret_loader_without_specifying_loader():
    args = helpers.MockArgs("some_name")
    with patch.object(SecretLoader, "register", return_value=None) as mock_register:
        secret = cli.get_secret_loader(args)

    assert not mock_register.called
    assert secret is secret


@patch("secret_loader.cli.get_custom_loader")
def test_get_secret_loader_for_custom_loader_without_priority(mock_get_custom_loader):
    custom_loader = "CustomLoader"
    custom_loader_path = f"some.module.{custom_loader}"
    mock_get_custom_loader.return_value = custom_loader

    args = helpers.MockArgs("some_name", custom_loader=custom_loader_path)
    with patch.object(SecretLoader, "register", return_value=None) as mock_register:
        secret = cli.get_secret_loader(args)

    assert mock_register.called
    assert mock_get_custom_loader.called

    mock_register.assert_called_once_with(custom_loader, cli.DEFAULT_PRIORITY)
    mock_get_custom_loader.assert_called_once_with(custom_loader_path)


@patch("secret_loader.cli.get_custom_loader")
def test_get_secret_loader_for_custom_loader_with_priority(mock_get_custom_loader):
    custom_loader = "CustomLoader"
    custom_loader_path = f"some.module.{custom_loader}"
    priority = "1000"
    mock_get_custom_loader.return_value = custom_loader

    args = helpers.MockArgs(
        "some_name", custom_loader=custom_loader_path, priority=float(priority),
    )
    with patch.object(SecretLoader, "register", return_value=None) as mock_register:
        secret = cli.get_secret_loader(args)

    assert mock_register.called
    assert mock_get_custom_loader.called

    mock_register.assert_called_once_with(custom_loader, float(priority))
    mock_get_custom_loader.assert_called_once_with(custom_loader_path)


def test_get_custom_loader(monkeypatch):
    custom_loader_name = "CustomLoader"
    custom_module_path = "some.module"
    custom_loader_path = f"{custom_module_path}.{custom_loader_name}"

    def mock_import_module(module_path):
        """Import a mock module"""

        assert custom_module_path == module_path

        class MockModule:
            def __init__(self):
                # Allow getattr to get the actual loader
                self.CustomLoader = custom_loader_name

        return MockModule()

    monkeypatch.setattr(importlib, "import_module", mock_import_module)

    loader = cli.get_custom_loader(custom_loader_path)
    assert loader == custom_loader_name


def test_list_loaders(capsys):
    class MockLoader:
        pass

    loader = LoaderContainer(
        loader=MockLoader(), priority=999, loader_class=MockLoader, args=[], kwargs={}
    )

    class MockSecret:
        def __init__(self, name=""):
            self.loaders = [loader]

    args = helpers.MockArgs(secret=MockSecret())
    cli.list_loaders(args)
    captured = capsys.readouterr()

    assert MockLoader.__name__ in captured.out
    assert "999" in captured.out


def test_loader_count_for_custom_loader(monkeypatch, valid_loader):
    args = helpers.MockArgs(custom_loader=valid_loader)

    monkeypatch.setattr(cli, "get_custom_loader", lambda x: valid_loader)

    secret = cli.get_secret_loader(args)

    assert len(secret.loaders) == len(cli.available_loaders) + 1


def test_loader_count_for_custom_loader_with_remove_loaders_arg(monkeypatch, valid_loader):
    args = helpers.MockArgs(custom_loader=valid_loader, remove_loaders=True)

    monkeypatch.setattr(cli, "get_custom_loader", lambda x: valid_loader)

    secret = cli.get_secret_loader(args)

    assert len(secret.loaders) == 1
    assert secret.loaders[0].loader_class == valid_loader


def test_loader_count_for_loader_with_remove_loaders_arg(valid_loader_class):
    args = helpers.MockArgs(loader=valid_loader_class, remove_loaders=True)

    secret = cli.get_secret_loader(args)

    assert len(secret.loaders) == 1
    assert secret.loaders[0].loader_class.__name__ == valid_loader_class
