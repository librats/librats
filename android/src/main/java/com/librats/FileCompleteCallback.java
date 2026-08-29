package com.librats;

/**
 * Notified when a transfer terminates, successfully or not.
 *
 * <p>Register with {@link RatsNode#onFileComplete(FileCompleteCallback)} before
 * {@link RatsNode#start()}; requires {@link RatsNode#enableFileTransfer(String)}.
 * Fires on an internal reactor thread.</p>
 */
@FunctionalInterface
public interface FileCompleteCallback {
    /**
     * @param transferId transfer identifier
     * @param success    true if the transfer completed successfully
     * @param path       final path of the transferred file/directory (may be null)
     */
    void onFileComplete(long transferId, String peerId, boolean success, String path);
}
