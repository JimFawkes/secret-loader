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
    "--name", "-n", help="Name of Secret to Load", type=str, required=True,
)

parser.add_argument("--fail", help="Fail if Secret is not Found", action="store_true")

parser.add_argument(
    "--loader", help="Specify a Loader to use", choices=available_loaders.keys(),
)


def get_secret_loader(args):
    if args.loader:
        secret = secrets.SecretLoader()
        secret.register(available_loaders[args.loader])
        return secret

    else:
        return secrets.secret


def secret_loader_cli(args):
    secret = get_secret_loader(args)
    try:
        print(secret(args.name))
    except secrets.SecretNotFoundError as e:
        if args.fail:
            raise e
        else:
            pass


def cli(parser=parser.parse_args):
    secret_loader_cli(args=parser())
