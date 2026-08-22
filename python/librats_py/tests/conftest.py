"""
Pytest configuration for the librats Python bindings.

The suites here need the native shared library; when it cannot be imported they
are skipped rather than failed, so a source checkout without a build still runs
the pure-Python tests.
"""

import os
import sys

import pytest

# Make the package importable straight from a source checkout.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from librats_py import RatsNode
    LIBRATS_AVAILABLE = True
except ImportError:
    RatsNode = None
    LIBRATS_AVAILABLE = False


def pytest_configure(config):
    config.addinivalue_line("markers", "integration: mark test as an integration test")
    config.addinivalue_line("markers", "slow: mark test as slow running")


def pytest_collection_modifyitems(config, items):
    if LIBRATS_AVAILABLE:
        return
    skip_native = pytest.mark.skip(reason="librats native library not available")
    for item in items:
        if "test_client" in item.nodeid or "test_integration" in item.nodeid:
            item.add_marker(skip_native)


@pytest.fixture
def rats_node():
    """An unstarted node on an ephemeral port, released after the test."""
    if not LIBRATS_AVAILABLE:
        pytest.skip("librats native library not available")
    node = RatsNode(0)
    try:
        yield node
    finally:
        node.destroy()


@pytest.fixture
def started_rats_node(rats_node):
    """The same node, already started."""
    rats_node.start()
    return rats_node
