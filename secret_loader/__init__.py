"""
Flexible Secret Loader to load secrets from any source with a simple API!

Copyright: (c) 2020, Moritz Eilfort
GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""

__version__ = "0.6"
__author__ = "Moritz Eilfort"
__author_email__ = "secret-loader@jimfawkes.com"
__url__ = "github.com/JimFawkes/secret-loader"
__license__ = "GPLv3+"
__copyright__ = f"Copyright 2020 {__author__}"

from . import base, exceptions, loaders, secrets

secret = secrets.secret

# Set default logging handler to avoid "No handler found" warnings.
import logging
from logging import NullHandler

logging.getLogger("secret_loader").addHandler(NullHandler())
