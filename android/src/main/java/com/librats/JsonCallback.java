package com.librats;

/**
 * Handed the JSON messages of one type.
 *
 * <p>Register with {@link RatsNode#onJson(String, JsonCallback)} or
 * {@link RatsNode#onceJson(String, JsonCallback)}. Runs on a reactor thread.</p>
 */
@FunctionalInterface
public interface JsonCallback {
    /**
     * @param peerId the sender, as authenticated by the handshake
     * @param json   compact JSON text
     */
    void onJsonMessage(String peerId, String json);
}
