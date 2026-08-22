package com.librats;

/**
 * Notified when a typed JSON message of a registered type arrives.
 *
 * <p>Register with {@link RatsNode#onJson(String, JsonCallback)} /
 * {@link RatsNode#onceJson(String, JsonCallback)}. Fires on an internal reactor
 * thread.</p>
 */
@FunctionalInterface
public interface JsonCallback {
    /**
     * @param peerId 64-char lowercase hex of the sending peer's id
     * @param json   compact JSON text; parse it with your JSON library of choice
     */
    void onJsonMessage(String peerId, String json);
}
