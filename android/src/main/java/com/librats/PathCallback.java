package com.librats;

/**
 * Notified with a path sample of every connected peer, every
 * {@link RatsNode.Config#pathSampleMs(int)} (100 ms if 0).
 *
 * <p>Register with {@link RatsNode#onPeerPath(PathCallback)} before
 * {@link RatsNode#start()}; registering one turns sampling on. Fires on an
 * internal reactor thread, once per peer per interval — keep it cheap, and
 * marshal to the UI thread before touching views.</p>
 */
@FunctionalInterface
public interface PathCallback {
    /**
     * @param peerId 64-char lowercase hex of the peer's self-certifying id
     * @param stats  the latest sample of the path to that peer
     */
    void onPeerPath(String peerId, PathStats stats);
}
