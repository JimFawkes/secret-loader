"""
This module defines all interactions with sensitive credentials.
Specifically it defines:
    1. A container to store a single key/value pair [Credential]
    2. A container to store several key/value pairs [Credentials] (Review naming)
    3. Machinery to load credentials from different sources
"""
import warnings

from collections.abc import Mapping
from typing import Union, Generator


class CredentialMutabilityError(Exception):
    """Encountered a mutable type"""


class Credential(Mapping):
    """Store a single Credential in the form of a key/value pair"""

    def __init__(self, name: str, secret: Union[int, str]) -> None:
        """
        Construct the Credential.

        Only allow certain immutable types as name and secret, to not allow any,
        changes to the values.
        """
        if isinstance(name, str):
            self._name: str = name
        else:
            raise CredentialMutabilityError(f"Credential.name only accepts variables of type str, not {type(name)}")
        if isinstance(secret, (int, str)):
            self._secret: Union[int, str] = secret
        else:
            raise CredentialMutabilityError(
                f"Credential.secret only accepts variables of types [str, tuple], not {type(name)}"
            )

    def __repr__(self) -> str:
        return f"Credential(name={self.name}, secret=***)"

    def __getitem__(self, key: str) -> Union[int, str]:
        if key == self.name:
            return self._secret
        else:
            raise KeyError(f"Credential has no key {key}")

    def __iter__(self) -> Generator[str, None, None]:
        yield self.name

    def __len__(self) -> int:
        return 1

    @property
    def name(self) -> str:
        return self._name

    @property
    def secret(self) -> str:
        return "***"

    def reveal(self) -> Union[int, str]:
        return self._secret


class Credentials(Mapping):
    """Store a list of credentials and provide the machinery to load them."""

    # TODO: Review keys(), items(), values(), get()
    # TODO: Review if getitem should return Credential or the revealed secret

    def __init__(self) -> None:
        self._secrets: dict = {}

    def __getitem__(self, key: str) -> Union[int, str]:
        return self._secrets[key].reveal()

    def __iter__(self) -> Generator[str, None, None]:
        for key in self._secrets.keys():
            yield key

    def __len__(self) -> int:
        return len(self._secrets)

    def __repr__(self):
        return f"Credentials()"

    def load(self, secret: dict) -> Union[int]:
        if not isinstance(secret, dict):
            raise NotImplementedError(f"Currently only supporting dicts")

        if not secret:
            return 0

        inserted_secrets: int = 0
        for key, value in secret.items():
            self._secrets[key] = Credential(name=key, secret=value)
            inserted_secrets += 1

        return inserted_secrets
