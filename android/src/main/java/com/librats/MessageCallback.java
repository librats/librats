package com.librats;

/**
 * Notified when raw bytes arrive on a named application channel.
 *
 * <p>Register per-channel with {@link RatsNode#on(String, MessageCallback)}
 * before {@link RatsNode#start()}. Fires on an internal reactor thread.</p>
 */
@FunctionalInterface
public interface MessageCallback {
    /**
     * @param peerId 64-char lowercase hex of the sending peer's id
     * @param data   the raw message bytes
     */
    void onMessage(String peerId, byte[] data);
}
