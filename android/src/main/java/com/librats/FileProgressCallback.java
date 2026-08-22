package com.librats;

/**
 * Notified as an in-flight transfer moves bytes.
 *
 * <p>Register with {@link RatsNode#onFileProgress(FileProgressCallback)} before
 * {@link RatsNode#start()}; requires {@link RatsNode#enableFileTransfer(String)}.
 * Fires on an internal reactor thread.</p>
 */
@FunctionalInterface
public interface FileProgressCallback {
    /**
     * @param transferId       transfer identifier
     * @param peerId           64-char lowercase hex of the remote peer's id
     * @param bytesTransferred bytes moved so far
     * @param totalBytes       total bytes for the transfer
     * @param status           where the transfer stands
     */
    void onFileProgress(long transferId, String peerId, long bytesTransferred, long totalBytes,
                        FileTransferStatus status);
}
