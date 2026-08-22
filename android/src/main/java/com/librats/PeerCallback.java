package com.librats;

/**
 * Notified when a peer connects or disconnects.
 *
 * <p>Register with {@link RatsNode#onPeerConnected(PeerCallback)} /
 * {@link RatsNode#onPeerDisconnected(PeerCallback)} before
 * {@link RatsNode#start()}. Fires on an internal reactor thread — marshal to the
 * UI thread before touching views.</p>
 */
@FunctionalInterface
public interface PeerCallback {
    /**
     * @param peerId 64-char lowercase hex of the peer's self-certifying id
     */
    void onPeer(String peerId);
}
