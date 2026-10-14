package com.librats;

/**
 * Congestion controller of every UDP connection ({@code rats_congestion_t}).
 * TCP connections use the kernel's and ignore this.
 */
public enum Congestion {
    /**
     * BBRv3, the default. Holds its rate through loss that is not congestion
     * (Wi-Fi, mobile, long paths).
     */
    BBR(0),
    /** NewReno with HyStart++. Backs off on every loss. */
    RENO(1);

    private final int value;

    Congestion(int value) {
        this.value = value;
    }

    /** @return the numeric {@code rats_congestion_t} value. */
    public int value() {
        return value;
    }
}
