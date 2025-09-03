"""
librats_py - Python bindings for librats P2P networking library

This package provides Python bindings for the librats C library, enabling
peer-to-peer networking, file transfers, NAT traversal, and more.
"""

from .core import RatsClient
from .exceptions import RatsError
from .enums import (
    RatsError as ErrorCode,
    ConnectionStrategy,
    MessageDataType,
    FileTransferStatus,
    LogLevel
)
from .callbacks import *

__version__ = "1.0.0"
__author__ = "librats contributors"
__license__ = "MIT"

__all__ = [
    'RatsClient',
    'RatsError', 
    'ErrorCode',
    'ConnectionStrategy',
    'MessageDataType', 
    'FileTransferStatus',
    'LogLevel'
]
