help_text = """
Secret-Loader

A unified way to laod secrets from different sources.

The secrets-loader will try to load a secret from a list of places:
 1. the current Environment
 2. a local .env file
 3. AWS SecretsManager

The result is printed to standard out, so besure to use this wisely.

"""

epilog = """
Version v0.1 - March 2020 - Jim Fawkes - src: github.com/JimFawkes/secret-loader
"""

import argparse
import importlib
import sys

from secret_loader import secrets

# This is depneding on all available default loaders. Might need a refactor if
# not all possible loaders are registered by default.
available_loaders = {
    loader.loader_class.__name__: loader.loader_class for loader in secrets.secret.loaders
}

parser = argparse.ArgumentParser(
    prog="secret_loader",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    description=help_text,
    epilog=epilog,
)

parser.add_argument(
    "--name", "-n", help="Name of Secret to Load", type=str,
)

parser.add_argument("--fail", help="Fail if Secret is not Found", action="store_true")

parser.add_argument(
    "--loader", help="Specify a Loader to use", choices=available_loaders.keys(),
)

# Currently this appears in the help message as one or more possible args. However
# Only one or two values are valid when this arg is passed.
# Not sure how to properly display this.
# Using `nargs=2,` does not solve the issue, because I want to allow a single arg to be valid
parser.add_argument(
    "--custom_loader",
    help="Use custom Loader, specified as an importable string e.g., 'some.module.CustomLoader'",
    type=str,
    nargs="+",
    metavar=("CUSTOM_LOADER", "PRIORITY"),
)

parser.add_argument(
    "--list_loaders", "-l", help="List all currently available loaders", action="store_true",
)


def get_custom_loader(loader_path):
    module_path, loader_name = loader_path.rsplit(".", 1)
    custom_module = importlib.import_module(module_path)
    loader = getattr(custom_module, loader_name)
    return loader


def list_loaders(args):
    print()
    print(f"Count) name : priority")
    print(f"-----) ---- : --------")
    for idx, loader in enumerate(args.secret.loaders):
        print(f"{idx}) {loader.loader_class.__name__} : {loader.priority}")


def get_secret_loader(args):
    def clean_loader(loader, priority=None):
        secret = secrets.SecretLoader()
        if priority:
            secret.register(loader, priority)
        else:
            secret.register(loader)
        return secret

    if args.custom_loader:
        loader = get_custom_loader(args.custom_loader_path)
        return clean_loader(loader, args.custom_loader_priority)
    elif args.loader:
        loader = available_loaders[args.loader]
        return clean_loader(loader)
    else:
        return secrets.secret


def parse_custom_loader(args):
    if not args.custom_loader:
        return args

    if 2 < len(args.custom_loader):
        # This might be changed later on, if needed
        parser.error("Only one loader priority pair is accepted")

    args.custom_loader_path = str(args.custom_loader[0])
    try:
        args.custom_loader_priority = float(args.custom_loader[1])
    except IndexError:
        args.custom_loader_priority = None
    except ValueError:
        parser.error("Expected float for priority --custom_loader CUSTOM_LOADER [PRIORITY]")

    return args


def parse_args(args):
    args = parse_custom_loader(args)
    args.secret = get_secret_loader(args)

    if args.list_loaders:
        list_loaders(args)
        sys.exit(0)

    elif not args.name:
        parser.error("A name is required (--name NAME)")

    return args


def secret_loader_cli(args):
    try:
        print(args.secret(args.name))
    except secrets.SecretNotFoundError as e:
        if args.fail:
            raise e
        else:
            pass


def cli(parser=parser.parse_args):
    args = parse_args(parser())
    secret_loader_cli(args)
