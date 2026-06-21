package com.librats;

/**
 * Callback invoked when a peer connection is established.
 *
 * <p>Register with {@link RatsClient#setConnectionCallback} before
 * {@link RatsClient#start()}. Fires on an internal reactor thread; marshal to
 * the UI thread before touching views.</p>
 */
public interface ConnectionCallback {
    /**
     * Called when a peer handshake completes.
     *
     * @param peerId 64-char lowercase hex of the connected peer's id
     */
    void onConnected(String peerId);
}
