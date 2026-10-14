package com.librats;

/**
 * Handed the messages that arrive on one named channel.
 *
 * <p>Register with {@link RatsNode#on(String, MessageCallback)} before
 * {@link RatsNode#start()}. Runs on a reactor thread.</p>
 */
@FunctionalInterface
public interface MessageCallback {
    /**
     * @param peerId the sender
     * @param data   the message bytes
     */
    void onMessage(String peerId, byte[] data);
}
