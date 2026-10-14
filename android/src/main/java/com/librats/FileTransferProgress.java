package com.librats;

/**
 * A snapshot of one file transfer ({@code rats_file_progress_t}), handed to
 * {@link FileProgressCallback}. Immutable.
 */
public final class FileTransferProgress {
    private final long transferId;
    private final String peerId;
    private final Direction direction;
    private final FileTransferStatus status;
    private final long bytesTransferred;
    private final long totalBytes;
    private final int filesCompleted;
    private final int totalFiles;
    private final double rateBytesPerSec;

    // Built by librats_jni.cpp; the signature there is (JLjava/lang/String;IIJJIID)V.
    FileTransferProgress(long transferId, String peerId, int direction, int status,
                         long bytesTransferred, long totalBytes, int filesCompleted,
                         int totalFiles, double rateBytesPerSec) {
        this.transferId = transferId;
        this.peerId = peerId;
        this.direction = Direction.fromValue(direction);
        this.status = FileTransferStatus.fromValue(status);
        this.bytesTransferred = bytesTransferred;
        this.totalBytes = totalBytes;
        this.filesCompleted = filesCompleted;
        this.totalFiles = totalFiles;
        this.rateBytesPerSec = rateBytesPerSec;
    }

    /** @return the transfer id, unique per peer. */
    public long transferId() {
        return transferId;
    }

    /** @return the other side's peer id. */
    public String peerId() {
        return peerId;
    }

    /** @return {@link Direction#OUTBOUND} if we send, {@link Direction#INBOUND} if we receive. */
    public Direction direction() {
        return direction;
    }

    /** @return where the transfer stands. */
    public FileTransferStatus status() {
        return status;
    }

    /** @return bytes moved so far. */
    public long bytesTransferred() {
        return bytesTransferred;
    }

    /** @return bytes in the whole transfer. */
    public long totalBytes() {
        return totalBytes;
    }

    /** @return files finished so far (a single-file transfer has one). */
    public int filesCompleted() {
        return filesCompleted;
    }

    /** @return files in the whole transfer. */
    public int totalFiles() {
        return totalFiles;
    }

    /** @return the recent, smoothed throughput in bytes per second. */
    public double rateBytesPerSec() {
        return rateBytesPerSec;
    }

    @Override
    public String toString() {
        return "FileTransferProgress{" + transferId + " " + direction + " " + status + " "
                + bytesTransferred + "/" + totalBytes + "}";
    }
}
