package com.librats;

/** Transport security mode ({@code rats_security_t}), fixed at construction. */
public enum Security {
    /** Noise XX: encrypted and mutually authenticated. The default. */
    NOISE(0),
    /** Unencrypted; peer ids are exchanged in the clear. */
    PLAINTEXT(1);

    private final int value;

    Security(int value) {
        this.value = value;
    }

    /** @return the numeric {@code rats_security_t} value. */
    public int value() {
        return value;
    }
}
