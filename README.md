# Secret-Loader

Flexible Secret Loader

[![test-action](https://github.com/JimFawkes/utils/workflows/run-tests/badge.svg)](https://github.com/JimFawkes/secret-loader/actions)
[![codecov](https://codecov.io/gh/JimFawkes/utils/branch/master/graph/badge.svg)](https://codecov.io/gh/JimFawkes/secret-loader)
[![python](https://img.shields.io/badge/python-v3.8%2B-blue)]
[![black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

# Requirements
```
python3.8+
```

## How to run the secrets_loader from the Command Line
```pytest
python -m secrets_loader --help

usage: secret_loader [-h] --name NAME [--fail] [--loader {EnvLoader,EnvFileLoader,AWSSecretsLoader}]

Secret-Loader

A unified way to laod secrets from different sources.

The secrets-loader will try to load a secret from a list of places:
 1. the current Environment
 2. a local .env file
 3. AWS SecretsManager

The result is printed to standard out, so besure to use this wisely.

optional arguments:
  -h, --help            show this help message and exit
  --name NAME, -n NAME  Name of Secret to Load
  --fail                Fail if Secret is not Found
  --loader {EnvLoader,EnvFileLoader,AWSSecretsLoader}
                        Specify a Loader to use

Version v0.1 - March 2020 - Jim Fawkes - src: github.com/JimFawkes/secret-loader

```

# Examples for CLI Usage
![secret_loader_cli_demo](docs/img/secret_loader_cli_demo_4.png)


## How to run the tests
```bash
pytest
```
