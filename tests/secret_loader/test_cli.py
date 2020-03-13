import pytest
from unittest.mock import patch

from secret_loader import cli, secrets


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


@patch("secret_loader.cli.secret")
def test_secret_loader_cli(mock_secret, capsys):
    secret_name = "secret_name"
    secret_value = "secret_value"
    mock_secret.return_value = secret_value

    class MockArgs:
        def __init__(self, name, fail=False):
            self.name = name
            self.fail = fail

    args = MockArgs(secret_name)
    cli.secret_loader_cli(args)

    captured = capsys.readouterr()
    cleaned_output = captured.out.replace("\n", "")

    assert cleaned_output == secret_value
