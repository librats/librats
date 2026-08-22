package com.librats;

/**
 * What the mesh has shown about this node's own NAT.
 *
 * <p>Derived from the endpoints datagram peers report observing this node's one
 * shared UDP socket at: two peers agreeing means one external port for every
 * peer, two disagreeing means a fresh mapping per peer. This replaces a STUN
 * server with the mesh the node already has.</p>
 */
public enum NatMapping {
    /** Not enough independent observations yet. */
    UNKNOWN(0),
    /** No NAT in the path. */
    OPEN(1),
    /** One external port for every peer — punchable. */
    ENDPOINT_INDEPENDENT(2),
    /** A fresh mapping per peer (symmetric) — punching cannot work from here. */
    ENDPOINT_DEPENDENT(3);

    private final int value;

    NatMapping(int value) {
        this.value = value;
    }

    /** @return the numeric {@code RATS_NAT_*} value. */
    public int value() {
        return value;
    }

    /**
     * @param value a numeric {@code RATS_NAT_*} value
     * @return the matching constant, or {@link #UNKNOWN} for an unknown value
     */
    public static NatMapping fromValue(int value) {
        for (NatMapping m : values()) {
            if (m.value == value) return m;
        }
        return UNKNOWN;
    }
}
