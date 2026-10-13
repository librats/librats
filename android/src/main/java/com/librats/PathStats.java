package com.librats;

/**
 * What the transport currently knows about the path to one peer — for a sender
 * that sizes its own output to the path (a live encoder) instead of letting the
 * queue find the limit. Mirrors {@code rats_path_stats_t}.
 *
 * <p>Rates are bits per second. Anything past {@link #bandwidthBps()} waits in
 * {@link #queuedBytes()}; {@code queuedBytes() * 8 / bandwidthBps()} is that wait
 * in seconds. Over TCP the figures are the kernel's, on Linux only.</p>
 *
 * <p>Obtained from {@link RatsNode#pathStats(String)} or handed to a
 * {@link PathCallback}. Immutable.</p>
 */
public final class PathStats {
    private final long bandwidthBps;
    private final boolean appLimited;
    private final long pacingBps;
    private final int srttUs;
    private final int minRttUs;
    private final long queuedBytes;
    private final long bytesInFlight;
    private final double loss;
    private final long bytesDelivered;
    private final long bytesLost;
    private final long liveSent;
    private final long liveExpired;
    private final long liveRepairBytes;

    // Built by librats_jni.cpp; the signature there is (JZJIIJJDJJJJJ)V.
    PathStats(long bandwidthBps, boolean appLimited, long pacingBps, int srttUs, int minRttUs,
              long queuedBytes, long bytesInFlight, double loss, long bytesDelivered,
              long bytesLost, long liveSent, long liveExpired, long liveRepairBytes) {
        this.bandwidthBps = bandwidthBps;
        this.appLimited = appLimited;
        this.pacingBps = pacingBps;
        this.srttUs = srttUs;
        this.minRttUs = minRttUs;
        this.queuedBytes = queuedBytes;
        this.bytesInFlight = bytesInFlight;
        this.loss = loss;
        this.bytesDelivered = bytesDelivered;
        this.bytesLost = bytesLost;
        this.liveSent = liveSent;
        this.liveExpired = liveExpired;
        this.liveRepairBytes = liveRepairBytes;
    }

    /** @return the congestion controller's bandwidth estimate; 0 = none yet. */
    public long bandwidthBps() {
        return bandwidthBps;
    }

    /**
     * @return true if the sender was not filling the path, so
     *         {@link #bandwidthBps()} is a floor (what was used), not the path
     */
    public boolean appLimited() {
        return appLimited;
    }

    /** @return the current release rate; 0 = unpaced. */
    public long pacingBps() {
        return pacingBps;
    }

    /** @return the smoothed round trip, in microseconds. */
    public int srttUs() {
        return srttUs;
    }

    /** @return the lowest round trip seen — the path without queues — in microseconds. */
    public int minRttUs() {
        return minRttUs;
    }

    /** @return bytes accepted for the peer, not yet sent. */
    public long queuedBytes() {
        return queuedBytes;
    }

    /** @return bytes sent, not yet acknowledged. */
    public long bytesInFlight() {
        return bytesInFlight;
    }

    /** @return the share of bytes lost over the last sample interval, 0..1. */
    public double loss() {
        return loss;
    }

    /** @return bytes acknowledged since the connection opened. */
    public long bytesDelivered() {
        return bytesDelivered;
    }

    /** @return bytes declared lost since the connection opened. */
    public long bytesLost() {
        return bytesLost;
    }

    /** @return live messages (a lifetime above 0) sent since the connection opened. */
    public long liveSent() {
        return liveSent;
    }

    /**
     * @return of those, how many were dropped because their lifetime ran out —
     *         the first thing a source asking for more than the path carries
     *         will see
     */
    public long liveExpired() {
        return liveExpired;
    }

    /**
     * @return bytes of repair symbols (forward error correction) sent with live
     *         messages on a lossy path — carried beside the source's own, so a
     *         source sized to {@link #bandwidthBps()} leaves room for them
     */
    public long liveRepairBytes() {
        return liveRepairBytes;
    }
}
