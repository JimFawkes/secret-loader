"""
Copyright: (c) 2020, Moritz Eilfort
GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

This module contains the base clases for secret_loader
"""

import inspect


def pretty_print_function(function):
    if inspect.isfunction(function):
        return f"<function '{function.__module__}.{function.__name__}'>"
    else:
        return function


class BaseClass:
    def __repr__(self):
        attribute_list = []
        for key, value in vars(self).items():
            value = pretty_print_function(value)
            attribute = f"{key}={value}"
            attribute_list.append(attribute)

        attributes = ", ".join(attribute_list)
        return f"{self.__class__.__name__}({attributes})"


class BaseLoader(BaseClass):
    def load(self, secret_name, **kwargs):
        raise NotImplementedError(f"A Loader needs to implement load(secret_name)")
