package com.librats;

/**
 * Why a peer connection ended ({@code rats_close_reason_t}), handed to
 * {@link PeerDisconnectCallback}.
 */
public enum CloseReason {
    /** We disconnected it. */
    LOCAL(0),
    /** The peer closed cleanly. */
    PEER_CLOSED(1),
    /** Connection reset or socket error. */
    PEER_RESET(2),
    /** The dial never completed. */
    CONNECT_FAILED(3),
    /** The secure handshake failed or timed out. */
    HANDSHAKE_FAILED(4),
    /** Malformed frame or decryption failure. */
    PROTOCOL_ERROR(5),
    /**
     * We kept sending while the peer's queue was already past its limit. The one
     * reason the application causes and can prevent: stop when
     * {@link RatsNode#peerWritable(String)} turns false and resume on
     * {@link RatsNode#onPeerWritable(PeerCallback)}. It never means one message
     * was too big.
     */
    SLOW_CONSUMER(6),
    /** The node is stopping. */
    SHUTDOWN(7),
    /** Replaced by another connection to the same peer. */
    DUPLICATE(8),
    /** Inbound refused: the peer cap was reached. */
    PEER_LIMIT(9),
    /** A UDP connection went silent. */
    IDLE_TIMEOUT(10),
    /** A dial racing over the other transport won. */
    DIAL_SUPERSEDED(11);

    private final int value;

    CloseReason(int value) {
        this.value = value;
    }

    /** @return the numeric {@code rats_close_reason_t} value. */
    public int value() {
        return value;
    }

    /** @return the constant for a {@code rats_close_reason_t} value; {@link #PEER_RESET} if unknown. */
    public static CloseReason fromValue(int value) {
        for (CloseReason r : values()) {
            if (r.value == value) return r;
        }
        return PEER_RESET;
    }
}
