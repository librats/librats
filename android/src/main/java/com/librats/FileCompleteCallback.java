package com.librats;

/**
 * Callback invoked when a transfer finishes (successfully or not).
 *
 * <p>Register with {@link RatsClient#setFileCompleteCallback} before
 * {@link RatsClient#start()}. Requires the file-transfer subsystem
 * ({@link RatsClient#enableFileTransfer(String)}). Fires on an internal reactor
 * thread.</p>
 */
public interface FileCompleteCallback {
    /**
     * Called when a transfer terminates.
     *
     * @param transferId unique transfer identifier
     * @param success    true if the transfer completed successfully
     * @param path       final path of the transferred file/directory (may be null)
     */
    void onFileComplete(long transferId, boolean success, String path);
}
