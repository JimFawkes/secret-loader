# Secret-Loader

Flexible Secret Loader

[![test-action](https://github.com/JimFawkes/utils/workflows/run-tests/badge.svg)](https://github.com/JimFawkes/utils/actions)
[![codecov](https://codecov.io/gh/JimFawkes/utils/branch/master/graph/badge.svg)](https://codecov.io/gh/JimFawkes/utils)

## How to run the secrets_loader from the Command Line
```pytest
python -m secrets_loader --help

usage: secret_loader [-h] --name NAME [--fail]

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

Version v0.1 - March 2020 - Jim Fawkes - src: github.com/JimFawkes/secret-loader

```

## How to run the tests
```bash
pytest
```
