"""
Pytest configuration for the librats Python bindings.

Tests marked ``native`` need the librats shared library; when it cannot be
loaded they are skipped, not failed. Point ``LIBRATS_LIBRARY_PATH`` at the
directory holding it if it is neither next to the package nor in ``build/``.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from librats_py.ctypes_wrapper import LibratsNotFoundError, get_librats  # noqa: E402

try:
    get_librats()
    LIBRATS_AVAILABLE = True
except LibratsNotFoundError:
    LIBRATS_AVAILABLE = False


def pytest_collection_modifyitems(config, items):
    if LIBRATS_AVAILABLE:
        return
    skip = pytest.mark.skip(reason="librats shared library not available")
    for item in items:
        if "native" in item.keywords:
            item.add_marker(skip)
