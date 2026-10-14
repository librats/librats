package com.librats;

/**
 * Told when a transfer ends, successfully or not.
 *
 * <p>Register with {@link RatsNode#onFileComplete(FileCompleteCallback)} before
 * {@link RatsNode#start()}. Runs on a reactor thread.</p>
 */
@FunctionalInterface
public interface FileCompleteCallback {
    /**
     * @param peerId     the other side's peer id
     * @param transferId the transfer id
     * @param success    whether it completed
     * @param path       where the file or directory ended up on this device
     */
    void onFileComplete(String peerId, long transferId, boolean success, String path);
}
