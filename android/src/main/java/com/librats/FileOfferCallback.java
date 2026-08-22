package com.librats;

/**
 * Notified when a peer offers a file or directory.
 *
 * <p>Register with {@link RatsNode#onFileOffer(FileOfferCallback)} before
 * {@link RatsNode#start()}; requires {@link RatsNode#enableFileTransfer(String)}.
 * Respond with {@link RatsNode#acceptFile(String, long, String)} or
 * {@link RatsNode#rejectFile(String, long)} — the {@code (peerId, transferId)}
 * pair names the offer. Fires on an internal reactor thread.</p>
 */
@FunctionalInterface
public interface FileOfferCallback {
    /**
     * @param peerId      64-char lowercase hex of the offering peer's id
     * @param transferId  transfer identifier, unique per peer
     * @param name        the offered file or directory name
     * @param size        total size in bytes
     * @param isDirectory true if the offer is a directory tree
     */
    void onFileOffer(String peerId, long transferId, String name, long size, boolean isDirectory);
}
