"""
Exceptions of the librats Python bindings, one per ``rats_error_t`` code.

:func:`check_error` turns a returned code into the matching exception.
"""

from .enums import RatsError as ErrorCode


class RatsError(Exception):
    """Base of every librats exception; ``error_code`` is the ``rats_error_t``."""

    code = ErrorCode.INTERNAL   # what a subclass raised without an explicit code carries

    def __init__(self, message: str, error_code: ErrorCode = None):
        super().__init__(message)
        self.error_code = self.code if error_code is None else error_code
        self.message = message

    def __str__(self):
        return f"{self.message} ({self.error_code.name})"


class RatsInvalidArgError(RatsError):
    """A NULL or malformed argument: bad peer id, bad JSON, impossible config."""
    code = ErrorCode.INVALID_ARG


class RatsNotStartedError(RatsError):
    """The call needs a started node."""
    code = ErrorCode.NOT_STARTED


class RatsAlreadyStartedError(RatsError):
    """The call is only allowed before start()."""
    code = ErrorCode.ALREADY_STARTED


class RatsNotEnabledError(RatsError):
    """The subsystem was not enabled with its enable_*()."""
    code = ErrorCode.NOT_ENABLED


class RatsNoSuchPeerError(RatsError):
    """The peer is not connected."""
    code = ErrorCode.NO_SUCH_PEER


class RatsNotFoundError(RatsError):
    """No such transfer."""
    code = ErrorCode.NOT_FOUND


class RatsDeclinedError(RatsError):
    """Nothing to do or nothing to try with: the peer is already connected, an
    attempt is running or cooling down, or no peer can help."""
    code = ErrorCode.DECLINED


class RatsBindError(RatsError):
    """start() could not open its sockets (the listen port is taken)."""
    code = ErrorCode.BIND


_ERROR_MAP = {
    ErrorCode.INVALID_ARG: RatsInvalidArgError,
    ErrorCode.NOT_STARTED: RatsNotStartedError,
    ErrorCode.ALREADY_STARTED: RatsAlreadyStartedError,
    ErrorCode.NOT_ENABLED: RatsNotEnabledError,
    ErrorCode.NO_SUCH_PEER: RatsNoSuchPeerError,
    ErrorCode.NOT_FOUND: RatsNotFoundError,
    ErrorCode.DECLINED: RatsDeclinedError,
    ErrorCode.BIND: RatsBindError,
}


def check_error(error_code: int, operation: str) -> None:
    """Raise the exception matching a non-OK ``rats_error_t``."""
    if error_code == ErrorCode.OK:
        return
    try:
        code = ErrorCode(error_code)
    except ValueError:
        raise RatsError(f"{operation} failed (unknown error {error_code})")
    raise _ERROR_MAP.get(code, RatsError)(f"{operation} failed", code)
