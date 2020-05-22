"""
Copyright: (c) 2020, Moritz Eilfort
GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

    Think about caching the results to reduce the roudtrips to aws

    TODO:
        - Add doc strings
        - Add logs
            * Add log when constructing InputLoader about the special case
        - Add Input Loader
            * Call loaders by name?
"""
import warnings

from collections.abc import Mapping
from collections import namedtuple
from pathlib import Path

from .base import BaseClass, BaseLoader
from .exceptions import (
    SecretNotFoundError,
    NoLoaderConfiguredError,
    ConstructLoaderError,
    SecretMutabilityError,
)
from .loaders import EnvLoader, EnvFileLoader, AWSSecretsLoader


LoaderContainer = namedtuple(
    "LoaderContainer", ("loader", "priority", "loader_class", "args", "kwargs")
)

# TODO: Think about renaming this class
class SecretLoader(BaseClass):
    DEFAULT_LOADER_PRIORITY = 0

    def __init__(self, loaders=[], *, parser=lambda x: x):
        self._loaders = self._construct_loader_list(loaders)
        self._parser = parser

    def __call__(self, secret_name, *, parser=None, **kwargs):
        if not self.loaders:
            raise NoLoaderConfiguredError(
                f"{self} has no loader configured, loaders={self.loaders}"
            )
        for loader in self.loaders:
            try:
                secret = loader.loader.load(secret_name, **kwargs)
                return self.parse(secret, parser=parser)
            except SecretNotFoundError as e:
                continue

        raise SecretNotFoundError(f"Could not load '{secret_name}' using loaders: {self.loaders}")

    @staticmethod
    def _construct_loader(loader, priority=None, *args, **kwargs):
        priority = priority or SecretLoader.DEFAULT_LOADER_PRIORITY
        return LoaderContainer(
            loader=loader(*args, **kwargs),
            priority=priority,
            loader_class=loader,
            args=args,
            kwargs=kwargs,
        )

    @staticmethod
    def _construct_loader_list(loaders):
        loader_list = []
        for loader in loaders:
            if callable(loader):
                loader_list.append(SecretLoader._construct_loader(loader))
            elif isinstance(loader, dict):
                loader_list.append(
                    SecretLoader._construct_loader(
                        loader["loader"], *loader["args"], **loader["kwargs"]
                    )
                )
            elif isinstance(loader, tuple):
                try:
                    loader_, priority, args, kwargs = loader
                except ValueError as e:
                    raise ConstructLoaderError(
                        f"Could not construct loader for '{loader}'. Hint: when passing in a tuple to construct a loader, four elements are expected (loader_class, priority, args, kwargs)"
                    ) from e
                loader_list.append(
                    SecretLoader._construct_loader(loader_, priority, *args, **kwargs)
                )
            else:
                raise ConstructLoaderError(f"Could not construct loader for '{loader}'")

        return loader_list

    @property
    def loaders(self):
        # NOTE: For loaders with the same priority, there is no guaranteed order
        return sorted(self._loaders, key=lambda x: x.priority, reverse=True)

    # Removed positional only argument to be compatible for python < 3.8
    # Consider making value  positional only in the future
    def parse(self, value, *, parser=None):

        if parser is None:
            return self._parser(value)
        else:
            return parser(value)

    def register(self, loader, priority=0, *args, **kwargs):
        constructed_loader = self._construct_loader(loader, priority, *args, **kwargs)
        self._loaders.append(constructed_loader)


# Set default priorities in a somewhat sensible way.
# Give Loaders with potential costs or long running a lower priority
# Leave 0 free since it is the default
# Give EnvLoader the highest priority
secret = SecretLoader()
secret.register(AWSSecretsLoader, priority=-10)
secret.register(EnvFileLoader, priority=-5)
secret.register(EnvLoader, priority=5)
