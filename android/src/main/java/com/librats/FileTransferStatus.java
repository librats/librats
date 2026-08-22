package com.librats;

/** Where a file transfer stands, as reported by {@link FileProgressCallback}. */
public enum FileTransferStatus {
    /** Offered, not yet accepted. */
    PENDING(0),
    /** Moving bytes. */
    ACTIVE(1),
    /** Paused by either side. */
    PAUSED(2),
    /** Finished successfully. */
    COMPLETED(3),
    /** Finished with an error. */
    FAILED(4),
    /** Cancelled by either side. */
    CANCELLED(5);

    private final int value;

    FileTransferStatus(int value) {
        this.value = value;
    }

    /** @return the numeric status value. */
    public int value() {
        return value;
    }

    /**
     * @param value a numeric status value
     * @return the matching constant, or {@link #FAILED} for an unknown value
     */
    public static FileTransferStatus fromValue(int value) {
        for (FileTransferStatus s : values()) {
            if (s.value == value) return s;
        }
        return FAILED;
    }
}
