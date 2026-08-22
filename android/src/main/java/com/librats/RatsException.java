package com.librats;

/**
 * Thrown by {@link RatsNode} when a native operation fails.
 *
 * <p>{@link #errorCode()} is the C ABI's {@code rats_error_t} as an
 * {@link ErrorCode}. The common ones are worth catching by value:
 * {@link ErrorCode#ALREADY_STARTED} (an {@code enable*} after
 * {@link RatsNode#start()}), {@link ErrorCode#NOT_ENABLED} (a subsystem used
 * before its {@code enable*}) and {@link ErrorCode#NO_SUCH_PEER}.</p>
 */
public class RatsException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final ErrorCode errorCode;

    public RatsException(String message) {
        super(message);
        this.errorCode = ErrorCode.INTERNAL;
    }

    public RatsException(String message, Throwable cause) {
        super(message, cause);
        this.errorCode = ErrorCode.INTERNAL;
    }

    public RatsException(ErrorCode errorCode, String operation) {
        super(operation + " failed: " + errorCode.message());
        this.errorCode = errorCode;
    }

    /** @return the underlying {@code rats_error_t}. */
    public ErrorCode errorCode() {
        return errorCode;
    }
}
