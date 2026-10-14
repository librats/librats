package com.librats;

/**
 * Told when a peer goes away, and why.
 *
 * <p>Register with {@link RatsNode#onPeerDisconnected(PeerDisconnectCallback)}
 * before {@link RatsNode#start()}. Runs on a reactor thread.</p>
 *
 * <p>The reason is worth branching on: a peer that left is one to redial, while
 * {@link CloseReason#SLOW_CONSUMER} means this node was sending faster than the
 * link drained, and redialing only repeats it.</p>
 */
@FunctionalInterface
public interface PeerDisconnectCallback {
    /**
     * @param peerId the peer's id
     * @param reason why the connection ended
     */
    void onPeerDisconnected(String peerId, CloseReason reason);
}
