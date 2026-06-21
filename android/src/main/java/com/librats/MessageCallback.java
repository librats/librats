package com.librats;

/**
 * Callback invoked when raw bytes arrive on a named application channel.
 *
 * <p>Register per-channel with {@link RatsClient#on(String, MessageCallback)}
 * before {@link RatsClient#start()}. Fires on an internal reactor thread.</p>
 */
public interface MessageCallback {
    /**
     * Called when a message is received on the channel this callback was
     * registered for.
     *
     * @param peerId 64-char lowercase hex of the sending peer's id
     * @param data   the raw message bytes
     */
    void onMessage(String peerId, byte[] data);
}
