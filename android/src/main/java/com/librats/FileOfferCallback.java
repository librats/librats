package com.librats;

/**
 * Callback invoked when a peer offers a file or directory.
 *
 * <p>Register with {@link RatsClient#setFileOfferCallback} before
 * {@link RatsClient#start()}. Requires the file-transfer subsystem
 * ({@link RatsClient#enableFileTransfer(String)}). Respond by calling
 * {@link RatsClient#acceptFile(String, long, String)} or
 * {@link RatsClient#rejectFile(String, long)}. Fires on an internal reactor
 * thread.</p>
 */
public interface FileOfferCallback {
    /**
     * Called when a peer offers a transfer.
     *
     * @param peerId      64-char lowercase hex of the offering peer's id
     * @param transferId  unique transfer identifier (use to accept/reject)
     * @param name        the offered file or directory name
     * @param size        total size in bytes
     * @param isDirectory true if the offer is a directory tree
     */
    void onFileOffer(String peerId, long transferId, String name, long size, boolean isDirectory);
}
