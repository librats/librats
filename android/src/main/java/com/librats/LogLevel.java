package com.librats;

/** Process-global logging verbosity ({@code rats_log_level_t}). */
public enum LogLevel {
    DEBUG(0),
    INFO(1),
    WARN(2),
    ERROR(3);

    private final int value;

    LogLevel(int value) {
        this.value = value;
    }

    /** @return the numeric {@code rats_log_level_t} value. */
    public int value() {
        return value;
    }
}
