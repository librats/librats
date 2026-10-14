package com.librats;

/**
 * Told when a peer offers a file or a directory tree.
 *
 * <p>Register with {@link RatsNode#onFileOffer(FileOfferCallback)} before
 * {@link RatsNode#start()}, and answer with
 * {@link RatsNode#acceptFile(String, long, String)} or
 * {@link RatsNode#rejectFile(String, long)}. Runs on a reactor thread.</p>
 */
@FunctionalInterface
public interface FileOfferCallback {
    /**
     * @param peerId      the offering peer
     * @param transferId  the transfer id, unique per peer
     * @param name        the file or directory name
     * @param size        total size in bytes
     * @param isDirectory whether it is a directory tree
     */
    void onFileOffer(String peerId, long transferId, String name, long size, boolean isDirectory);
}
