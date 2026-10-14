package com.librats;

import java.util.Collections;
import java.util.Set;

/**
 * What the node knows about one connected peer ({@code rats_peer_info_t}), from
 * {@link RatsNode#peerInfo(String)}. Immutable.
 */
public final class PeerInfo {
    private final Transport transport;
    private final Set<Transport> transports;
    private final Direction direction;
    private final String address;

    // Built by librats_jni.cpp; the signature there is (IIILjava/lang/String;)V.
    PeerInfo(int transport, int transportsMask, int direction, String address) {
        Transport t = Transport.fromValue(transport);
        this.transport = t != null ? t : Transport.TCP;
        this.transports = Collections.unmodifiableSet(Transport.fromMask(transportsMask));
        this.direction = Direction.fromValue(direction);
        this.address = address == null || address.isEmpty() ? null : address;
    }

    /** @return the wire this connection runs on; {@link Transport#RELAY} for a relayed peer. */
    public Transport transport() {
        return transport;
    }

    /**
     * @return the transports the peer says it accepts. Empty means it did not
     *         say — no information, not "none".
     */
    public Set<Transport> transports() {
        return transports;
    }

    /** @return whether we dialed the peer or it dialed us. */
    public Direction direction() {
        return direction;
    }

    /**
     * @return where the peer can be dialed, {@code "ip:port"} or {@code "[ip]:port"};
     *         null until known
     */
    public String address() {
        return address;
    }

    @Override
    public String toString() {
        return "PeerInfo{" + transport + ", " + direction + ", " + address + ", accepts " + transports + "}";
    }
}
