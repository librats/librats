package com.librats;

/**
 * Notified when a peer goes away, and why.
 *
 * <p>Register with {@link RatsNode#onPeerDisconnected(PeerDisconnectCallback)}
 * before {@link RatsNode#start()}. Fires on an internal reactor thread — marshal
 * to the UI thread before touching views.</p>
 *
 * <p>The reason is worth branching on. A peer that simply left is one to redial;
 * {@code "RATS_CLOSE_SLOW_CONSUMER"} means <em>this</em> node was sending faster
 * than the link drained, and redialing that one only repeats the overload — the
 * answer there is {@link RatsNode#peerWritable(String)} and
 * {@link RatsNode#onPeerWritable(PeerCallback)}.</p>
 */
@FunctionalInterface
public interface PeerDisconnectCallback {
    /**
     * @param peerId 64-char lowercase hex of the peer's self-certifying id
     * @param reason why the connection ended, e.g. {@code "RATS_CLOSE_PEER_CLOSED"}
     */
    void onPeerDisconnected(String peerId, String reason);
}
