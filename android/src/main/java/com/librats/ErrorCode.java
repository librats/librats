package com.librats;

/**
 * The C ABI's {@code rats_error_t}. Every value but {@link #OK} reaches Java as a
 * {@link RatsException}.
 */
public enum ErrorCode {
    /** Success. */
    OK(0, "OK"),
    /** A null or malformed argument: a bad peer id, invalid JSON, a payload too large to be live. */
    INVALID_ARG(1, "invalid argument"),
    /** The call needs a started node. */
    NOT_STARTED(2, "node not started"),
    /** Only allowed before {@link RatsNode#start()}. */
    ALREADY_STARTED(3, "node already started"),
    /** The subsystem was not enabled with its {@code enable*} method. */
    NOT_ENABLED(4, "subsystem not enabled"),
    /** The peer is not connected. */
    NO_SUCH_PEER(5, "no such peer"),
    /** No such transfer. */
    NOT_FOUND(6, "not found"),
    /**
     * Nothing to do or nothing to try with: the peer is already connected, an
     * attempt is already running or cooling down, or no peer can help.
     */
    DECLINED(7, "declined"),
    /** {@link RatsNode#start()} could not open its sockets. */
    BIND(8, "could not bind"),
    /** Anything else. */
    INTERNAL(9, "internal error");

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

    /** @return a short description. */
    public String message() {
        return message;
    }

    /** @return the constant for a {@code rats_error_t} value; {@link #INTERNAL} if unknown. */
    public static ErrorCode fromCode(int code) {
        for (ErrorCode e : values()) {
            if (e.code == code) return e;
        }
        return INTERNAL;
    }
}
