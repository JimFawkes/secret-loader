"""
Copyright: (c) 2020, Moritz Eilfort
GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""

import logging
from collections import namedtuple

from .base import BaseClass, pretty_print_function
from .exceptions import ConstructLoaderError, NoLoaderConfiguredError, SecretNotFoundError
from .loaders import AWSSecretsLoader, EnvFileLoader, EnvLoader

logger = logging.getLogger("secret_loader.secrets")

LoaderContainer = namedtuple(
    "LoaderContainer", ("loader", "priority", "loader_class", "args", "kwargs")
)

# TODO: Think about renaming this class
class SecretLoader(BaseClass):
    """
    Class to wrap and bundle the mechanics of loading secrets from different
    sources. These sources might be environment variables, a file, user input,
    external systems (e.g. AWS SecretsManager). The actual loading of secrets
    is done by registered loaders.

    A loader may also generate a secret/token and return that.

    Parameters
    ----------
    loaders : list
        A list of loaders to pre-register. This is optional, loaders may also
        be registered using `SecretLoader.register()`.
    parser : callable
        A parser used as default for all secrets from all loaders

    Examples
    --------
    ```
    from secret_loader import SecretLoader
    from secret_loader.loaders import EnvLoader

    loaders = [
        {
            "loader": EnvLoader,
            "priority": 0,
            "args": (),
            "kwargs": {}
        },
    ]

    secret = SecretLoader(loaders)

    secret("IMPORTANT_SECRET")
    "top_secret_12345678"
    ```
    """

    DEFAULT_LOADER_PRIORITY = 0

    def __init__(self, loaders=[], *, parser=lambda x: x):
        self._loaders = self._construct_loader_list(loaders)
        self._parser = parser
        logger.debug(f"Initialized: {self}")

    def __call__(self, secret_name, *, parser=None, **kwargs):
        """Retrieve a secret value by the given name using the registered loaders.

        This method probes all registered loaders with the given secret_name
        and returns the first hit, after post processing/parsing the value.
        If no loader returned a value, a `SecretNotFoundError` is raised.

        Parameters
        ----------
        secret_name : str
            The name of the secret to load
        parser : callable
            A callable to post process the retrieved value. See `SecretLoader.parser()`
            for more details.
        kwargs : Optional keyword arguments
            Passed to the load method of the individual loaders.

        Returns
        -------
        secret_value : any

        Examples
        --------
        ```
        from secret_loader import secret

        secret("important-secret")
        "top_secret_12345678"
        ```
        """

        if not self.loaders:
            raise NoLoaderConfiguredError(
                f"{self} has no loader configured, loaders={self.loaders}"
            )
        for loader in self.loaders:
            try:
                logger.debug(f"Trying to load {secret_name} using {loader.loader_class}")
                secret = loader.loader.load(secret_name, **kwargs)
                logger.debug(f"Succsessfully loaded {secret_name} using {loader.loader_class}")
                return self.parse(secret, parser=parser)
            except SecretNotFoundError as e:
                continue

        raise SecretNotFoundError(f"Could not load '{secret_name}' using loaders: {self.loaders}")

    @staticmethod
    def _construct_loader(loader, priority=None, *args, **kwargs):
        """Private method to construct a loader given a loader class and priority"""

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
        """Private method to construct multiple loaders"""

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
        """List registered Loaders, sorted by priority"""

        # NOTE: For loaders with the same priority, there is no guaranteed order
        return sorted(self._loaders, key=lambda x: x.priority, reverse=True)

    # Removed positional only argument to be compatible for python < 3.8
    # Consider making value  positional only in the future
    def parse(self, value, *, parser=None):
        """Post Process the given value.

        This method is called after a value is retrieved and allows for post
        processing of the given value. It is possible to to set a parser at
        time of instantiation or by passing in a callable when retrieving a
        a secret.

        Parameters
        ----------
        value : any, required
            The retrieved secret value.
        parser : callable, optional (default: self._parser)
            The function called to actually process the value.

        Returns
        -------
        value : any
            Parsed/Post Processed secret value returned from parser callable.

        Examples
        --------
        ```
        from secret_loader import secret
        import json

        secret("backend/important-database", parser=json.loads)
        {'host': 'my-host-name',
         'port': 1234,
         'password': '12345678',
         'username': 'some-user'}

        secret("comma-separated-secret", parser=lambda x: x.split(","))
        ["first", "second", "third"]
        ```
        """

        if parser is None:
            logger.debug(
                f"Parsing secret using parser={pretty_print_function(self._parser)} (Hint: Default Parser or Class Level Parser)"
            )
            return self._parser(value)
        else:
            logger.debug(
                f"Parsing secret using parser={pretty_print_function(parser)} (Hint: Parser explicitly passed)"
            )
            return parser(value)

    def register(self, loader, priority=0, *args, **kwargs):
        """Register a new loader.

        This method registers a new loader with a given priority and loader
        specific args and kwargs to be probed for secret retrieval. The priority
        allows to set precedence of individual loaders over others. See example
        below. This method is used to register the default loaders sush as EnvLoader
        or AWSSecretsLoader.

        Parameters
        ----------
        loader : class
            The new loader class to be instantiated and registered.
        priority : int, optional (default=0)
            Priority of the new loader, used to determine which loader is
            probebed first.
        args, kwargs : any
            Positional and Keyword arguments to be passed to the loaders
            __init__ method at instantiation time.

        Returns
        -------
        None

        Examples
        --------
        ```
        from secret_loader import secret

        secret.register(AWSSecretsLoader, priority=-10)
        secret.register(EnvFileLoader, priority=-5)
        secret.register(EnvLoader, priority=5)

        This will ensure that retrieving a secret will first be attempted in
        the following order:
            1. EnvLoader
            2. EnvFileLoader
            3. AWSSecretsLoader
        ```
        """

        constructed_loader = self._construct_loader(loader, priority, *args, **kwargs)
        self._loaders.append(constructed_loader)
        logger.debug(
            f"Registered Loader: '{constructed_loader.loader_class}' with priority={constructed_loader.priority}"
        )


# Set default priorities in a somewhat sensible way.
# Give Loaders with potential costs or long running a lower priority
# Leave 0 free since it is the default
# Give EnvLoader the highest priority
secret = SecretLoader()
secret.register(AWSSecretsLoader, priority=-10)
secret.register(EnvFileLoader, priority=-5)
secret.register(EnvLoader, priority=5)
