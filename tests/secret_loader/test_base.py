"""
Copyright: (c) 2020, Moritz Eilfort
GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""

import pytest

from secret_loader.base import BaseLoader

# ----------------------------------------------------------------------------
# Test BaseLoader
# ----------------------------------------------------------------------------


def test_base_loader_has_load_method():
    base_loader = BaseLoader()

    with pytest.raises(NotImplementedError):
        base_loader.load("SOME_VAR")


def test_base_loader_load_method_requires_attribute():
    base_loader = BaseLoader()

    with pytest.raises(TypeError):
        base_loader.load()


def test_base_loader_has_repr():
    base_loader = BaseLoader()

    assert "BaseLoader(" in str(base_loader)


def test_base_loader_pass_kwargs():
    base_loader = BaseLoader()

    with pytest.raises(NotImplementedError):
        base_loader.load("SOME_VAR", some_dummy_var="abc", some_other_var="abc", some_int=43)
