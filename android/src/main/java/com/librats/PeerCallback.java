package com.librats;

/**
 * Notified about a peer, by id alone.
 *
 * <p>Register with {@link RatsNode#onPeerConnected(PeerCallback)} or
 * {@link RatsNode#onPeerWritable(PeerCallback)} before {@link RatsNode#start()}.
 * Fires on an internal reactor thread — marshal to the UI thread before touching
 * views.</p>
 *
 * <p>Disconnects use {@link PeerDisconnectCallback} instead: they carry a reason,
 * which is what tells a peer that left apart from one this node was sending to
 * too fast.</p>
 */
@FunctionalInterface
public interface PeerCallback {
    /**
     * @param peerId 64-char lowercase hex of the peer's self-certifying id
     */
    void onPeer(String peerId);
}
