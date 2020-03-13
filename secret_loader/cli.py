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

from secret_loader.secrets import secret, SecretNotFoundError

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


def secret_loader_cli(args=parser.parse_args()):
    try:
        print(secret(args.name))
    except SecretNotFoundError as e:
        if args.fail:
            raise e
        else:
            pass
