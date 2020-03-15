import importlib
import pytest
from unittest.mock import patch

from secret_loader import cli, secrets


class MockArgs:
    def __init__(
        self,
        name="",
        fail=False,
        loader=None,
        custom_loader=None,
        list_loaders=False,
        secret=None,
        priority=cli.DEFAULT_PRIORITY,
        remove_loaders=False,
        **kwargs,
    ):
        self.name = name
        self.fail = fail
        self.loader = loader
        self.custom_loader = custom_loader
        self.list_loaders = list_loaders
        self.secret = secret
        self.priority = float(priority)
        self.remove_loaders = remove_loaders


@pytest.fixture
def get_parse_args(monkeypatch):

    monkeypatch.setattr(cli, "get_secret_loader", lambda x: lambda x: x)
    monkeypatch.setattr(cli, "list_loaders", lambda x: None)

    def parse_args(args=[]):
        return cli.parse_args(cli.parser.parse_args(args))

    return parse_args


@pytest.fixture
def valid_loader_class():
    return list(cli.available_loaders)[0]


@pytest.fixture
def valid_loader(valid_loader_class):
    return cli.available_loaders[valid_loader_class]


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


def test_secret_loader_cli(capsys):
    secret_name = "secret_name"
    secret_value = "secret_value"

    args = MockArgs(secret_name, secret=lambda x: secret_value)
    cli.secret_loader_cli(args)

    captured = capsys.readouterr()
    cleaned_output = captured.out.replace("\n", "")

    assert cleaned_output == secret_value


def test_secret_loader_cli_fail_silently(capsys):
    secret_name = "secret_name"

    def raise_on_call(val):
        raise secrets.SecretNotFoundError()

    args = MockArgs(secret_name, secret=raise_on_call)

    cli.secret_loader_cli(args)

    captured = capsys.readouterr()
    cleaned_output = captured.out.replace("\n", "")

    assert cleaned_output == ""


def test_secret_loader_cli_fail():
    secret_name = "secret_name"

    def raise_on_call(val):
        raise secrets.SecretNotFoundError()

    args = MockArgs(secret_name, fail=True, secret=raise_on_call)

    with pytest.raises(secrets.SecretNotFoundError):
        cli.secret_loader_cli(args)


@patch("secret_loader.cli.secret_loader_cli")
@patch("secret_loader.cli.parse_args")
def test_cli(mock_secret_loader_cli, mock_parse_args):
    cli.cli(parser=lambda: None)

    assert mock_secret_loader_cli.called
    assert mock_parse_args.called


def test_available_loader_count():
    assert 2 < len(cli.available_loaders)


def test_get_secret_loader_for_specific_loader(valid_loader, valid_loader_class):
    args = MockArgs("some_name", loader=valid_loader_class)

    with patch.object(secrets.SecretLoader, "register", return_value=None) as mock_register:
        secret = cli.get_secret_loader(args)

    assert mock_register.called
    mock_register.assert_called_once_with(valid_loader, cli.DEFAULT_PRIORITY)


def test_get_secret_loader_without_specifying_loader():
    args = MockArgs("some_name")
    with patch.object(secrets.SecretLoader, "register", return_value=None) as mock_register:
        secret = cli.get_secret_loader(args)

    assert not mock_register.called
    assert secret is secrets.secret


@patch("secret_loader.cli.get_custom_loader")
def test_get_secret_loader_for_custom_loader_without_priority(mock_get_custom_loader):
    custom_loader = "CustomLoader"
    custom_loader_path = f"some.module.{custom_loader}"
    mock_get_custom_loader.return_value = custom_loader

    args = MockArgs("some_name", custom_loader=custom_loader_path)
    with patch.object(secrets.SecretLoader, "register", return_value=None) as mock_register:
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

    args = MockArgs("some_name", custom_loader=custom_loader_path, priority=float(priority),)
    with patch.object(secrets.SecretLoader, "register", return_value=None) as mock_register:
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

    loader = secrets.LoaderContainer(
        loader=MockLoader(), priority=999, loader_class=MockLoader, args=[], kwargs={}
    )

    class MockSecret:
        def __init__(self, name=""):
            self.loaders = [loader]

    args = MockArgs(secret=MockSecret())
    cli.list_loaders(args)
    captured = capsys.readouterr()

    assert MockLoader.__name__ in captured.out
    assert "999" in captured.out


def test_loader_count_for_custom_loader(monkeypatch, valid_loader):
    args = MockArgs(custom_loader=valid_loader)

    monkeypatch.setattr(cli, "get_custom_loader", lambda x: valid_loader)

    secret = cli.get_secret_loader(args)

    assert len(secret.loaders) == len(cli.available_loaders) + 1


def test_loader_count_for_custom_loader_with_remove_loaders_arg(monkeypatch, valid_loader):
    args = MockArgs(custom_loader=valid_loader, remove_loaders=True)

    monkeypatch.setattr(cli, "get_custom_loader", lambda x: valid_loader)

    secret = cli.get_secret_loader(args)

    assert len(secret.loaders) == 1
    assert secret.loaders[0].loader_class == valid_loader


def test_loader_count_for_loader_with_remove_loaders_arg(monkeypatch, valid_loader_class):
    args = MockArgs(loader=valid_loader_class, remove_loaders=True)

    secret = cli.get_secret_loader(args)

    assert len(secret.loaders) == 1
    assert secret.loaders[0].loader_class.__name__ == valid_loader_class
