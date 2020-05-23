"""
Flexible Secret Loader to load secrets from any source with a simple API!

Copyright: (c) 2020, Moritz Eilfort
GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""

__version__ = "0.3"

from . import loaders
from . import base
from . import exceptions
from . import secrets

secret = secrets.secret

# Set default logging handler to avoid "No handler found" warnings.
import logging
from logging import NullHandler

logging.getLogger("secret_loader").addHandler(NullHandler())
