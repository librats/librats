package com.librats;

/**
 * Callback invoked when a typed JSON message of a registered type arrives.
 *
 * <p>Register per-type with {@link RatsClient#onJson(String, JsonMessageCallback)}
 * (or {@link RatsClient#onceJson}) before {@link RatsClient#start()}. Requires
 * the JSON subsystem ({@link RatsClient#enableJson()}). Fires on an internal
 * reactor thread.</p>
 */
public interface JsonMessageCallback {
    /**
     * Called when a JSON message of the registered type is received.
     *
     * @param peerId 64-char lowercase hex of the sending peer's id
     * @param json   compact JSON text payload
     */
    void onJsonMessage(String peerId, String json);
}
