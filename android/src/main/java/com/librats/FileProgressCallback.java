package com.librats;

/**
 * Callback invoked with progress updates for an in-flight transfer.
 *
 * <p>Register with {@link RatsClient#setFileProgressCallback} before
 * {@link RatsClient#start()}. Requires the file-transfer subsystem
 * ({@link RatsClient#enableFileTransfer(String)}). Fires on an internal reactor
 * thread.</p>
 */
public interface FileProgressCallback {
    /**
     * Called as bytes are transferred.
     *
     * @param transferId       unique transfer identifier
     * @param peerId           64-char lowercase hex of the remote peer's id
     * @param bytesTransferred bytes moved so far
     * @param totalBytes       total bytes for the transfer
     * @param status           subsystem status code for the transfer
     */
    void onFileProgress(long transferId, String peerId, long bytesTransferred, long totalBytes, int status);
}
