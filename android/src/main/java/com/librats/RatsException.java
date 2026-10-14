package com.librats;

/**
 * Thrown by {@link RatsNode} when a native call fails. {@link #errorCode()} is
 * the C ABI's {@code rats_error_t}; the ones worth catching by value are
 * {@link ErrorCode#NO_SUCH_PEER}, {@link ErrorCode#DECLINED},
 * {@link ErrorCode#NOT_ENABLED} and {@link ErrorCode#ALREADY_STARTED}.
 */
public class RatsException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final ErrorCode errorCode;

    /** A failure with no {@code rats_error_t} behind it; {@link #errorCode()} is {@link ErrorCode#INTERNAL}. */
    public RatsException(String message) {
        super(message);
        this.errorCode = ErrorCode.INTERNAL;
    }

    /** A failed native call: "{@code operation} failed: {@code <description>}". */
    public RatsException(ErrorCode errorCode, String operation) {
        super(operation + " failed: " + errorCode.message());
        this.errorCode = errorCode;
    }

    /** @return the underlying {@code rats_error_t}. */
    public ErrorCode errorCode() {
        return errorCode;
    }
}
