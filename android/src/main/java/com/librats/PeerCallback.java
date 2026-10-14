package com.librats;

/**
 * Told about a peer, by id: it connected
 * ({@link RatsNode#onPeerConnected(PeerCallback)}), or its full send queue
 * drained ({@link RatsNode#onPeerWritable(PeerCallback)}).
 *
 * <p>Register before {@link RatsNode#start()}. Runs on a reactor thread — hop to
 * the UI thread before touching views.</p>
 */
@FunctionalInterface
public interface PeerCallback {
    /** @param peerId the peer's id, 64-char lowercase hex */
    void onPeer(String peerId);
}
