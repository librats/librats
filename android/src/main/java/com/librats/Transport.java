package com.librats;

import java.util.EnumSet;

/**
 * Which wire a peer connection runs on ({@code rats_transport_t}).
 *
 * <p>Both carry the identical protocol and the identical encrypted handshake;
 * they differ only in how the ordered, reliable byte stream underneath is
 * obtained. UDP is the default first choice for a dial: one socket means one NAT
 * mapping for every peer, and the source port a peer observes is the port it can
 * dial back — which is what makes hole punching possible at all.</p>
 */
public enum Transport {
    /** One kernel socket per peer. */
    TCP(0, 0x1),
    /** Reliable stream over the one shared UDP socket. */
    UDP(1, 0x2);

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

    /** @return this transport's bit in a {@code RATS_TRANSPORT_MASK_*} bitmask. */
    public int mask() {
        return mask;
    }

    /**
     * @param value a numeric {@code rats_transport_t} value
     * @return the matching constant, or null if the value is unknown
     */
    public static Transport fromValue(int value) {
        for (Transport t : values()) {
            if (t.value == value) return t;
        }
        return null;
    }

    /**
     * Decodes a {@code RATS_TRANSPORT_MASK_*} bitmask.
     *
     * @param mask the bitmask
     * @return the transports it names; empty for 0
     */
    public static EnumSet<Transport> fromMask(int mask) {
        EnumSet<Transport> set = EnumSet.noneOf(Transport.class);
        for (Transport t : values()) {
            if ((mask & t.mask) != 0) set.add(t);
        }
        return set;
    }
}
