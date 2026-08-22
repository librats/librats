package com.librats;

/**
 * The C ABI's {@code rats_error_t} result codes.
 *
 * <p>{@link #OK} is success; every other value surfaces as a
 * {@link RatsException} thrown by the failing {@link RatsNode} method.</p>
 */
public enum ErrorCode {
    /** Success. */
    OK(0, "OK"),
    /** Null or malformed argument — a bad peer id, a null pointer, invalid JSON. */
    INVALID_ARG(1, "Invalid argument"),
    /** The operation requires a started node. */
    NOT_STARTED(2, "Node not started"),
    /** An {@code enable*} was called after {@link RatsNode#start()}. */
    ALREADY_STARTED(3, "Node already started"),
    /** A subsystem was used before its {@code enable*}. */
    NOT_ENABLED(4, "Subsystem not enabled"),
    /** The peer is not connected, or the transfer id is unknown. */
    NO_SUCH_PEER(5, "No such peer or transfer"),
    /** The listener could not bind during {@link RatsNode#start()}. */
    BIND(6, "Listen/bind failed"),
    /** Anything else. */
    INTERNAL(7, "Internal error");

    private final int code;
    private final String message;

    ErrorCode(int code, String message) {
        this.code = code;
        this.message = message;
    }

    /** @return the numeric {@code rats_error_t} value. */
    public int code() {
        return code;
    }

    /** @return a human-readable description. */
    public String message() {
        return message;
    }

    /**
     * @param code a numeric {@code rats_error_t} value
     * @return the matching constant, or {@link #INTERNAL} for an unknown code
     */
    public static ErrorCode fromCode(int code) {
        for (ErrorCode e : values()) {
            if (e.code == code) return e;
        }
        return INTERNAL;
    }
}
