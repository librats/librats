package com.librats;

/**
 * Handed a path sample of every connected peer, every
 * {@link RatsNode.Config#pathSampleMs(int)} (100 ms if 0).
 *
 * <p>Register with {@link RatsNode#onPeerPath(PathCallback)} before
 * {@link RatsNode#start()}; registering one turns sampling on. Runs on a reactor
 * thread once per peer per interval, so keep it cheap.</p>
 */
@FunctionalInterface
public interface PathCallback {
    /**
     * @param peerId the peer's id
     * @param stats  the latest sample of the path to it
     */
    void onPeerPath(String peerId, PathStats stats);
}
