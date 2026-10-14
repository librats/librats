package com.librats;

/** Where a file transfer stands ({@code rats_file_status_t}). */
public enum FileTransferStatus {
    /** Offered, not answered yet. */
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

    /** @return the numeric {@code rats_file_status_t} value. */
    public int value() {
        return value;
    }

    /** @return the constant for a {@code rats_file_status_t} value; {@link #FAILED} if unknown. */
    public static FileTransferStatus fromValue(int value) {
        for (FileTransferStatus s : values()) {
            if (s.value == value) return s;
        }
        return FAILED;
    }
}
