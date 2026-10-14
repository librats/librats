package com.librats;

/**
 * What the mesh has shown about this node's own NAT ({@code rats_nat_mapping_t}),
 * judged from where UDP peers report seeing its socket.
 */
public enum NatMapping {
    /** Not enough independent observations yet. */
    UNKNOWN(0),
    /** No NAT in the path. */
    OPEN(1),
    /** One external port for every peer: punchable. */
    ENDPOINT_INDEPENDENT(2),
    /** A new mapping per peer (symmetric NAT): punching cannot work from here; a relay can. */
    ENDPOINT_DEPENDENT(3);

    private final int value;

    NatMapping(int value) {
        this.value = value;
    }

    /** @return the numeric {@code rats_nat_mapping_t} value. */
    public int value() {
        return value;
    }

    /** @return the constant for a {@code rats_nat_mapping_t} value; {@link #UNKNOWN} if unknown. */
    public static NatMapping fromValue(int value) {
        for (NatMapping m : values()) {
            if (m.value == value) return m;
        }
        return UNKNOWN;
    }
}
