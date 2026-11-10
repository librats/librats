"""
Wheel tagging for the librats Python bindings. All metadata lives in pyproject.toml.

The package is pure Python on the surface but ships the native librats shared
library (loaded through ctypes), so a wheel only works on the platform it was
built on. It does not touch the Python C API, though, so one wheel per platform
serves every Python 3 version: tag it ``py3-none-<platform>``.
"""

from setuptools import setup
from setuptools.command.bdist_wheel import bdist_wheel
from setuptools.dist import Distribution


class BinaryDistribution(Distribution):
    # Install into platlib (the wheel root) rather than .data/purelib, where
    # auditwheel refuses to find a shared library.
    def has_ext_modules(self):
        return True


class PlatformWheel(bdist_wheel):
    def get_tag(self):
        _, _, plat = super().get_tag()
        return "py3", "none", plat


setup(distclass=BinaryDistribution, cmdclass={"bdist_wheel": PlatformWheel})
