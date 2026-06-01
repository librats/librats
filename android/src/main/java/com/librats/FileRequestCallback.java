package com.librats;

/**
 * Callback interface for incoming transfer offers (file or directory).
 */
public interface FileRequestCallback {
    /**
     * Called when a peer offers a file or directory to this client. Respond by
     * calling {@link RatsClient#acceptFileTransfer} or
     * {@link RatsClient#rejectFileTransfer} with the given transfer ID.
     *
     * @param peerId The ID of the offering peer
     * @param transferId The unique transfer identifier
     * @param remotePath Always empty in the push-only model (kept for signature stability)
     * @param filename The offered file/directory name
     */
    void onFileRequest(String peerId, String transferId, String remotePath, String filename);
}
