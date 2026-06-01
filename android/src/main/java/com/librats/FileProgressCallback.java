package com.librats;

/**
 * Callback interface for file and directory transfer progress events.
 */
public interface FileProgressCallback {
    /**
     * Called with progress updates for an in-flight transfer.
     *
     * @param transferId The unique transfer identifier
     * @param progressPercent Completion percentage (0-100)
     * @param status The transfer status (e.g. "IN_PROGRESS", "COMPLETED", "FAILED", "CANCELLED")
     */
    void onFileProgress(String transferId, int progressPercent, String status);
}
