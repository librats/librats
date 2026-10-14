package com.librats;

/**
 * Told when a dial to a numeric address failed over every transport tried —
 * one made by {@link RatsNode#connect(String, int)} or by a discovery
 * subsystem. A dial by hostname is not reported.
 *
 * <p>Register with {@link RatsNode#onDialFailed(DialFailedCallback)} before
 * {@link RatsNode#start()}. Runs on a reactor thread.</p>
 */
@FunctionalInterface
public interface DialFailedCallback {
    /** @param address the address dialed, {@code "ip:port"} or {@code "[ip]:port"} */
    void onDialFailed(String address);
}
