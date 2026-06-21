"""
Exception classes for librats Python bindings.

Exceptions are keyed off the C ABI ``rats_error_t`` codes (see :class:`RatsError`
in ``enums.py``). Use :func:`check_error` to turn a returned code into an
exception.
"""

from .enums import RatsError as ErrorCode


class RatsError(Exception):
    """Base exception for librats errors.

    ``error_code`` is the originating :class:`~librats_py.enums.RatsError`
    (``rats_error_t``) value when the error came from the C library.
    """

    def __init__(self, message: str, error_code: ErrorCode = ErrorCode.INTERNAL):
        super().__init__(message)
        self.error_code = error_code
        self.message = message

    def __str__(self):
        return f"{self.message} (error code: {self.error_code.name})"


class RatsInvalidArgError(RatsError):
    """RATS_ERR_INVALID_ARG — null/malformed argument."""

    def __init__(self, message: str = "Invalid argument"):
        super().__init__(message, ErrorCode.INVALID_ARG)


class RatsNotStartedError(RatsError):
    """RATS_ERR_NOT_STARTED — operation requires a started node."""

    def __init__(self, message: str = "Node is not started"):
        super().__init__(message, ErrorCode.NOT_STARTED)


class RatsAlreadyStartedError(RatsError):
    """RATS_ERR_ALREADY_STARTED — enable/attach called after start()."""

    def __init__(self, message: str = "Node is already started"):
        super().__init__(message, ErrorCode.ALREADY_STARTED)


class RatsNotEnabledError(RatsError):
    """RATS_ERR_NOT_ENABLED — subsystem not enabled."""

    def __init__(self, message: str = "Subsystem is not enabled"):
        super().__init__(message, ErrorCode.NOT_ENABLED)


class RatsNoSuchPeerError(RatsError):
    """RATS_ERR_NO_SUCH_PEER — peer not connected or transfer id not found."""

    def __init__(self, message: str = "No such peer or transfer"):
        super().__init__(message, ErrorCode.NO_SUCH_PEER)


class RatsBindError(RatsError):
    """RATS_ERR_BIND — listen/bind failed during start()."""

    def __init__(self, message: str = "Failed to bind listen socket"):
        super().__init__(message, ErrorCode.BIND)


class RatsConnectionError(RatsError):
    """Raised when a connection attempt fails."""

    def __init__(self, message: str = "Connection failed",
                 error_code: ErrorCode = ErrorCode.INTERNAL):
        super().__init__(message, error_code)


# Map error codes to their dedicated exception type.
_ERROR_MAP = {
    ErrorCode.INVALID_ARG: RatsInvalidArgError,
    ErrorCode.NOT_STARTED: RatsNotStartedError,
    ErrorCode.ALREADY_STARTED: RatsAlreadyStartedError,
    ErrorCode.NOT_ENABLED: RatsNotEnabledError,
    ErrorCode.NO_SUCH_PEER: RatsNoSuchPeerError,
    ErrorCode.BIND: RatsBindError,
}


def check_error(error_code: int, operation: str = "Operation") -> None:
    """Raise the appropriate exception for a non-OK ``rats_error_t`` value.

    Args:
        error_code: The integer ``rats_error_t`` returned by a C function.
        operation: Human-readable description used in the exception message.
    """
    if error_code == ErrorCode.OK:
        return

    try:
        error_enum = ErrorCode(error_code)
    except ValueError:
        raise RatsError(f"{operation} failed (unknown error {error_code})",
                        ErrorCode.INTERNAL)

    message = f"{operation} failed"
    exc_type = _ERROR_MAP.get(error_enum)
    if exc_type is not None:
        raise exc_type(message)
    raise RatsError(message, error_enum)
