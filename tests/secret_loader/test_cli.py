import pytest
from unittest.mock import patch

from secret_loader import cli, secrets


class MockArgs:
    def __init__(self, name, fail=False, loader=None, **kwargs):
        self.name = name
        self.fail = fail
        self.loader = loader


def test_argument_parser_exits_for_missing_required_args():
    with pytest.raises(SystemExit) as e:
        args = cli.parser.parse_args()


def test_argument_parser_takes_a_secret_name():
    secret_name = "SOME_NAME"
    args = cli.parser.parse_args(["--name", f"{secret_name}"])

    assert args.name == secret_name


def test_argument_parser_sets_arg_fail_as_false_by_default():
    secret_name = "SOME_NAME"
    args = cli.parser.parse_args(["--name", f"{secret_name}"])

    assert args.fail is False


def test_argument_parser_sets_arg_fail_as_true_when_provided():
    secret_name = "SOME_NAME"
    args = cli.parser.parse_args(["--name", f"{secret_name}", "--fail"])

    assert args.fail is True


def test_argument_parser_sets_arg_loader_as_none_by_default():
    secret_name = "SOME_NAME"
    args = cli.parser.parse_args(["--name", f"{secret_name}"])

    assert args.loader is None


def test_argument_parser_exits_for_unknown_loader():
    secret_name = "SOME_NAME"
    unknown_loader = "no_real_loader"

    with pytest.raises(SystemExit) as e:
        cli.parser.parse_args(["--name", secret_name, "--loader", unknown_loader])


def test_argument_parser_accepts_valid_loader():
    secret_name = "SOME_NAME"
    valid_loader = list(cli.available_loaders)[0]

    args = cli.parser.parse_args(["--name", secret_name, "--loader", valid_loader])

    assert args.loader == valid_loader


@patch("secret_loader.secrets.secret")
def test_secret_loader_cli(mock_secret, capsys):
    secret_name = "secret_name"
    secret_value = "secret_value"
    mock_secret.return_value = secret_value

    args = MockArgs(secret_name)
    cli.secret_loader_cli(args)

    captured = capsys.readouterr()
    cleaned_output = captured.out.replace("\n", "")

    assert cleaned_output == secret_value


@patch("secret_loader.secrets.secret")
def test_secret_loader_cli_fail_silently(mock_secret, capsys):
    secret_name = "secret_name"
    secret_value = "secret_value"
    mock_secret.side_effect = secrets.SecretNotFoundError()

    args = MockArgs(secret_name)
    cli.secret_loader_cli(args)

    captured = capsys.readouterr()
    cleaned_output = captured.out.replace("\n", "")

    assert cleaned_output == ""


@patch("secret_loader.secrets.secret")
def test_secret_loader_cli_fail(mock_secret, capsys):
    secret_name = "secret_name"
    secret_value = "secret_value"
    mock_secret.side_effect = secrets.SecretNotFoundError()

    args = MockArgs(secret_name, fail=True)
    with pytest.raises(secrets.SecretNotFoundError):
        cli.secret_loader_cli(args)


@patch("secret_loader.cli.secret_loader_cli")
def test_cli(mock_secret_loader_cli):
    argument = "name"
    cli.cli(parser=lambda: argument)

    assert mock_secret_loader_cli.called
    mock_secret_loader_cli.assert_called_with(args=argument)


def test_available_loader_count():
    assert 2 < len(cli.available_loaders)


def test_get_secret_loader_for_specific_loader():
    loader_class = list(cli.available_loaders)[0]
    args = MockArgs("some_name", loader=loader_class)
    with patch.object(secrets.SecretLoader, "register", return_value=None) as mock_register:
        secret = cli.get_secret_loader(args)

    assert mock_register.called
    mock_register.assert_called_once_with(cli.available_loaders[loader_class])


def test_get_secret_loader_without_specifying_loader():
    args = MockArgs("some_name")
    with patch.object(secrets.SecretLoader, "register", return_value=None) as mock_register:
        secret = cli.get_secret_loader(args)

    assert not mock_register.called
    assert secret is secrets.secret
