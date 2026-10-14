package com.librats;

/**
 * Told how a transfer is moving, in either direction.
 *
 * <p>Register with {@link RatsNode#onFileProgress(FileProgressCallback)} before
 * {@link RatsNode#start()}. Runs on a reactor thread.</p>
 */
@FunctionalInterface
public interface FileProgressCallback {
    /** @param progress a snapshot of the transfer */
    void onFileProgress(FileTransferProgress progress);
}
