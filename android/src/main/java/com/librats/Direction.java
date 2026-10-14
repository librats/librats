package com.librats;

/**
 * Which side started something ({@code rats_direction_t}): a connection, or a
 * file transfer.
 */
public enum Direction {
    /** We dialed the peer, or we are the one sending the file. */
    OUTBOUND(0),
    /** The peer dialed us, or we are the one receiving the file. */
    INBOUND(1);

    private final int value;

    Direction(int value) {
        this.value = value;
    }

    /** @return the numeric {@code rats_direction_t} value. */
    public int value() {
        return value;
    }

    /** @return the constant for a {@code rats_direction_t} value; {@link #OUTBOUND} if unknown. */
    public static Direction fromValue(int value) {
        return value == INBOUND.value ? INBOUND : OUTBOUND;
    }
}
