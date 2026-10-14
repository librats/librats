package com.librats;

import java.util.EnumSet;

/**
 * Which wire a peer connection runs on ({@code rats_transport_t}).
 *
 * <p>UDP and TCP carry the same protocol under the same encrypted handshake. UDP
 * is what a dial tries first by default: every peer shares one socket and so one
 * NAT mapping, which is also what makes hole punching possible. {@link #RELAY} is
 * a connection carried through another peer; it is only ever reported, never
 * chosen, so it has no bit in a transports mask.</p>
 */
public enum Transport {
    /** The library's own transport on the one shared UDP socket. */
    UDP(0, 0x2),
    /** One kernel socket per peer. */
    TCP(1, 0x1),
    /** Carried through another peer's connection; see {@link RatsNode#enableRelay(boolean)}. */
    RELAY(2, 0x0);

    private final int value;
    private final int mask;

    Transport(int value, int mask) {
        this.value = value;
        this.mask = mask;
    }

    /** @return the numeric {@code rats_transport_t} value. */
    public int value() {
        return value;
    }

    /** @return this transport's {@code RATS_TRANSPORT_MASK_*} bit; 0 for {@link #RELAY}. */
    public int mask() {
        return mask;
    }

    /** @return the constant for a {@code rats_transport_t} value, or null if unknown. */
    public static Transport fromValue(int value) {
        for (Transport t : values()) {
            if (t.value == value) return t;
        }
        return null;
    }

    /** @return the transports named by a {@code RATS_TRANSPORT_MASK_*} bitmask; empty for 0. */
    public static EnumSet<Transport> fromMask(int mask) {
        EnumSet<Transport> set = EnumSet.noneOf(Transport.class);
        for (Transport t : values()) {
            if ((mask & t.mask) != 0) set.add(t);
        }
        return set;
    }

    /** @return the bitmask of a set of transports ({@link #RELAY} contributes nothing). */
    public static int toMask(Iterable<Transport> transports) {
        int mask = 0;
        for (Transport t : transports) mask |= t.mask;
        return mask;
    }
}
