package com.librats;

/**
 * Exception thrown by {@link RatsClient} for failed native operations.
 *
 * <p>The {@link #getErrorCode()} mirrors the C ABI {@code rats_error_t} enum
 * (see {@code src/bindings/rats.h}). {@link RatsClient#OK} (0) is success; any
 * other value is an error.</p>
 */
public class RatsException extends RuntimeException {
    private final int errorCode;

    public RatsException(String message) {
        super(message);
        this.errorCode = RatsClient.ERR_INTERNAL;
    }

    public RatsException(int errorCode) {
        super(getErrorMessage(errorCode));
        this.errorCode = errorCode;
    }

    public RatsException(String message, int errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    public RatsException(String message, Throwable cause) {
        super(message, cause);
        this.errorCode = RatsClient.ERR_INTERNAL;
    }

    /** @return the underlying {@code rats_error_t} code. */
    public int getErrorCode() {
        return errorCode;
    }

    /** Human-readable name for a {@code rats_error_t} value. */
    public static String getErrorMessage(int errorCode) {
        switch (errorCode) {
            case RatsClient.OK:
                return "OK";
            case RatsClient.ERR_INVALID_ARG:
                return "Invalid argument";
            case RatsClient.ERR_NOT_STARTED:
                return "Node not started";
            case RatsClient.ERR_ALREADY_STARTED:
                return "Node already started";
            case RatsClient.ERR_NOT_ENABLED:
                return "Subsystem not enabled";
            case RatsClient.ERR_NO_SUCH_PEER:
                return "No such peer or transfer";
            case RatsClient.ERR_BIND:
                return "Listen/bind failed";
            case RatsClient.ERR_INTERNAL:
                return "Internal error";
            default:
                return "Unknown error (" + errorCode + ")";
        }
    }
}
