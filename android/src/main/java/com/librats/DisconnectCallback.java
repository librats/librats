package com.librats;

/**
 * Callback invoked when a peer disconnects.
 *
 * <p>Register with {@link RatsClient#setDisconnectCallback} before
 * {@link RatsClient#start()}. Fires on an internal reactor thread.</p>
 */
public interface DisconnectCallback {
    /**
     * Called when a peer connection is torn down.
     *
     * @param peerId 64-char lowercase hex of the disconnected peer's id
     */
    void onDisconnected(String peerId);
}
