"""
Copyright: (c) 2020, Moritz Eilfort
GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

This module contains the exceptions for secret_loader
"""


class SecretNotFoundError(Exception):
    """Could not load Secret"""


class NoLoaderConfiguredError(Exception):
    """No Loader was provided"""


class ConstructLoaderError(Exception):
    """Could not construct loader"""


class SecretMutabilityError(Exception):
    """Encountered a mutable type"""
