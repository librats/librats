package com.librats;

import android.util.Log;

import java.util.EnumSet;

/**
 * One librats node — a Java wrapper over the C ABI
 * ({@code src/librats/bindings/rats.h}).
 *
 * <p>On its own a node is secure transport (Noise XX over TCP <b>or</b> the
 * library's reliable stream over UDP, both on the same port), a self-certifying
 * peer id, manual dialing, and raw messaging on named channels — nothing else.
 * Discovery (DHT/mDNS), pub/sub, typed JSON messaging, file transfer, NAT port
 * mapping, hole punching, RTT probing and reconnection are opt-in subsystems.</p>
 *
 * <p><b>Ordering matters.</b> Enable subsystems and register callbacks
 * <em>before</em> {@link #start()}. Enabling after start throws with
 * {@link ErrorCode#ALREADY_STARTED}; using a subsystem before its enable throws
 * with {@link ErrorCode#NOT_ENABLED}.</p>
 *
 * <p><b>Threading.</b> Callbacks fire on an internal reactor thread — do not
 * block in them, and marshal to the UI thread (e.g. {@code runOnUiThread})
 * before touching views.</p>
 *
 * <p><b>Errors.</b> Every fallible method throws {@link RatsException}; getters
 * return their value. Peer ids are 64-char lowercase hex strings.</p>
 *
 * <pre>{@code
 * try (RatsNode node = new RatsNode(new RatsNode.Config()
 *         .listenPort(8080)
 *         .dataDir(getFilesDir().getAbsolutePath()))) {
 *     node.onPeerConnected(id -> Log.i(TAG, "+ " + id));
 *     node.on("chat", (id, data) -> Log.i(TAG, new String(data)));
 *     node.enableDht();
 *     node.start();
 *     ...
 * }
 * }</pre>
 */
public class RatsNode implements AutoCloseable {
    private static final String TAG = "RatsNode";

    static {
        try {
            System.loadLibrary("rats_jni");
        } catch (UnsatisfiedLinkError e) {
            Log.e(TAG, "Failed to load native library", e);
            throw e;
        }
    }

    private long nativePtr;

    /**
     * Node configuration, mirroring {@code rats_config_t}. Every setter returns
     * {@code this}, so it reads as one expression:
     *
     * <pre>{@code
     * new RatsNode.Config().listenPort(8080).protocol("myapp/1.0").maxPeers(50)
     * }</pre>
     *
     * <p>Every field has a working default; set only what you care about.</p>
     */
    public static final class Config {
        int listenPort = 0;
        boolean enableListen = true;
        String bindAddress = null;
        Security security = Security.NOISE;
        String dataDir = null;
        String protocol = null;
        long maxPeers = 0;
        boolean enableTcp = true;
        boolean enableUdp = true;
        Transport preferredTransport = Transport.UDP;
        int transportFallbackMs = 1200;

        /** Inbound port shared by both transports; 0 (the default) = ephemeral. */
        public Config listenPort(int port) {
            this.listenPort = port;
            return this;
        }

        /** False makes a dial-only node with no listener. Default true. */
        public Config enableListen(boolean enable) {
            this.enableListen = enable;
            return this;
        }

        /** Bind address; null (the default) selects the {@code "::"} dual-stack wildcard. */
        public Config bindAddress(String address) {
            this.bindAddress = address;
            return this;
        }

        /** Transport security. Default {@link Security#NOISE}. */
        public Config security(Security security) {
            this.security = security;
            return this;
        }

        /**
         * Directory for persistent state — the node's identity, the DHT routing
         * table, the reconnection store. Null (the default) gives a fresh
         * identity every run. On Android, {@code context.getFilesDir()}.
         */
        public Config dataDir(String dir) {
            this.dataDir = dir;
            return this;
        }

        /**
         * Application protocol bound into the handshake, e.g. {@code "myapp/1.0"};
         * null selects {@code "librats/1.0"}. Two nodes whose protocol differs
         * cannot complete a handshake.
         */
        public Config protocol(String protocol) {
            this.protocol = protocol;
            return this;
        }

        /** Established-peer cap; 0 (the default) = unlimited. */
        public Config maxPeers(long maxPeers) {
            this.maxPeers = maxPeers;
            return this;
        }

        /** Accept and dial over TCP. Default true. */
        public Config enableTcp(boolean enable) {
            this.enableTcp = enable;
            return this;
        }

        /** Accept and dial over the datagram transport. Default true. */
        public Config enableUdp(boolean enable) {
            this.enableUdp = enable;
            return this;
        }

        /** Which transport a dial tries first. Default {@link Transport#UDP}. */
        public Config preferredTransport(Transport transport) {
            this.preferredTransport = transport;
            return this;
        }

        /**
         * How long the preferred transport dials alone before the other is raced
         * alongside it; 0 disables the fallback. Default 1200 ms.
         */
        public Config transportFallbackMs(int ms) {
            this.transportFallbackMs = ms;
            return this;
        }
    }

    // ===================== construction =====================

    /**
     * Creates a listening node with all defaults but the port.
     *
     * @param listenPort inbound port, or 0 for an ephemeral one
     */
    public RatsNode(int listenPort) {
        this(new Config().listenPort(listenPort));
    }

    /**
     * Creates a node from a {@link Config}.
     *
     * @param config the configuration; null selects all defaults
     */
    public RatsNode(Config config) {
        if (config == null) config = new Config();
        nativePtr = nativeCreateConfig(
                config.listenPort,
                config.enableListen,
                config.bindAddress,
                config.security.value(),
                config.dataDir,
                config.protocol,
                config.maxPeers,
                config.enableTcp,
                config.enableUdp,
                config.preferredTransport.value(),
                config.transportFallbackMs);
        if (nativePtr == 0) {
            throw new RatsException("Failed to create the native rats node");
        }
    }

    // ===================== lifecycle =====================

    /**
     * Binds the listener and brings up every enabled subsystem.
     *
     * @throws RatsException with {@link ErrorCode#BIND} if the listener could not
     *         bind, or {@link ErrorCode#ALREADY_STARTED} if it is already running
     */
    public void start() {
        check(nativeStart(ptr()), "start");
    }

    /** Stops the node and closes all connections. Idempotent. */
    public void stop() {
        if (nativePtr != 0) nativeStop(nativePtr);
    }

    /**
     * Stops the node and releases the native resources. The instance is inert
     * afterwards — further calls throw. Idempotent.
     */
    @Override
    public void close() {
        if (nativePtr != 0) {
            nativeDestroy(nativePtr);
            nativePtr = 0;
        }
    }

    /**
     * Safety net for a node that was never {@link #close()}d. Prefer
     * try-with-resources; a finalizer runs at an unpredictable time, if ever.
     */
    @Override
    @SuppressWarnings({"deprecation", "removal"})
    protected void finalize() throws Throwable {
        try {
            close();
        } finally {
            super.finalize();
        }
    }

    // ===================== identity / info =====================

    /** @return the bound listen port (the actual one when 0 was requested). */
    public int listenPort() {
        return nativeListenPort(ptr());
    }

    /** @return our self-certifying peer id, 64-char lowercase hex. */
    public String localId() {
        return nativeLocalId(ptr());
    }

    /** @return the application protocol bound into the handshake, e.g. {@code "librats/1.0"}. */
    public String protocol() {
        return nativeProtocol(ptr());
    }

    /**
     * The transports this node is actually running. May be narrower than the
     * config asked for — a UDP socket that could not be bound leaves the node
     * TCP-only rather than failing to start.
     *
     * @return the running transports; empty before {@link #start()} and after
     *         {@link #stop()}
     */
    public EnumSet<Transport> transports() {
        return Transport.fromMask(nativeTransports(ptr()));
    }

    // ===================== connections =====================

    /**
     * Dials a peer. Non-blocking: success surfaces as
     * {@link #onPeerConnected(PeerCallback)}.
     *
     * @throws RatsException with {@link ErrorCode#INVALID_ARG} if the host cannot
     *         be parsed or resolved
     */
    public void connect(String host, int port) {
        check(nativeConnect(ptr(), host, port), "connect to " + host + ":" + port);
    }

    /** @return the number of currently-connected peers. */
    public long peerCount() {
        return nativePeerCount(ptr());
    }

    /** @return hex ids of currently-connected peers; never null. */
    public String[] peerIds() {
        String[] ids = nativePeerIds(ptr());
        return ids != null ? ids : new String[0];
    }

    /** Caps established peers (0 = unlimited). May be called before or after start. */
    public void setMaxPeers(long maxPeers) {
        nativeSetMaxPeers(ptr(), maxPeers);
    }

    /** @return the current established-peer cap (0 = unlimited). */
    public long maxPeers() {
        return nativeMaxPeers(ptr());
    }

    /**
     * @param peerId a connected peer
     * @return which wire that peer's link runs on, or null if it is not connected
     */
    public Transport peerTransport(String peerId) {
        int value = nativePeerTransport(ptr(), peerId);
        return value < 0 ? null : Transport.fromValue(value);
    }

    /**
     * The transports a connected peer advertised in its identify message.
     *
     * @param peerId a connected peer
     * @return what it advertised, or null if it is not connected. An empty set
     *         means the peer did not say (an older build) — "no information",
     *         not "no transports".
     */
    public EnumSet<Transport> peerTransports(String peerId) {
        int mask = nativePeerTransports(ptr(), peerId);
        return mask < 0 ? null : Transport.fromMask(mask);
    }

    // ===================== raw channel messaging =====================

    /** Sends raw bytes to one peer over a named channel. */
    public void send(String peerId, String channel, byte[] data) {
        check(nativeSend(ptr(), peerId, channel, data), "send on '" + channel + "'");
    }

    /** Sends raw bytes over a named channel to every connected peer. */
    public void broadcast(String channel, byte[] data) {
        check(nativeBroadcast(ptr(), channel, data), "broadcast on '" + channel + "'");
    }

    /**
     * Whether this peer's send queue still has room; false too for a peer that is
     * not connected.
     *
     * <p>{@link #send} returning normally only means the message was queued, never
     * that it arrived — so if you send in bulk, this is how you learn you are
     * outrunning the link. False means pause: what you just sent was queued like
     * anything else and nothing was dropped, but keep piling on and the peer is
     * dropped with {@code RATS_CLOSE_SLOW_CONSUMER}. Wait for
     * {@link #onPeerWritable(PeerCallback)}, or poll this. It is not a size limit
     * — one message of any size is always queued.</p>
     */
    public boolean peerWritable(String peerId) {
        return nativePeerWritable(ptr(), peerId);
    }

    /** Registers an additive handler for a named channel. Call before start. */
    public void on(String channel, MessageCallback callback) {
        check(nativeOn(ptr(), channel, callback), "register handler for '" + channel + "'");
    }

    // ===================== peer events (before start) =====================

    /** Sets the peer-connected callback. Call before start. */
    public void onPeerConnected(PeerCallback callback) {
        check(nativeOnPeerConnected(ptr(), callback), "register peer-connected callback");
    }

    /**
     * Sets the peer-disconnected callback, which is told why the peer went.
     * Call before start.
     */
    public void onPeerDisconnected(PeerDisconnectCallback callback) {
        check(nativeOnPeerDisconnected(ptr(), callback), "register peer-disconnected callback");
    }

    /**
     * Sets the callback fired when a peer whose send queue had filled past its
     * mark has drained back under it — the other half of
     * {@link #peerWritable(String)} returning false. Call before start.
     */
    public void onPeerWritable(PeerCallback callback) {
        check(nativeOnPeerWritable(ptr(), callback), "register peer-writable callback");
    }

    // ===================== discovery (enable before start) =====================

    /**
     * Enables DHT discovery: announce on and search a key on the mainline DHT,
     * dialing what it finds.
     *
     * @param dhtPort      DHT port, or 0 for an ephemeral one
     * @param discoveryKey app namespace; null uses the node's protocol, so only
     *                     same-protocol peers discover each other
     */
    public void enableDht(int dhtPort, String discoveryKey) {
        check(nativeEnableDht(ptr(), dhtPort, discoveryKey), "enable DHT");
    }

    /** Enables DHT discovery on an ephemeral port under the node's protocol. */
    public void enableDht() {
        enableDht(0, null);
    }

    /** Enables local-network mDNS discovery. Call before start. */
    public void enableMdns() {
        check(nativeEnableMdns(ptr()), "enable mDNS");
    }

    // ===================== NAT traversal (enable before start) =====================

    /**
     * Enables automatic NAT port forwarding for the listen port.
     *
     * @param enableUpnp   run the UPnP IGD backend
     * @param enableNatpmp run the NAT-PMP backend
     */
    public void enablePortMapping(boolean enableUpnp, boolean enableNatpmp) {
        check(nativeEnablePortMapping(ptr(), enableUpnp, enableNatpmp), "enable port mapping");
    }

    /** Enables both port-mapping backends. */
    public void enablePortMapping() {
        enablePortMapping(true, true);
    }

    /**
     * Enables UDP hole punching: reach a peer that no port forwarding made
     * reachable, by arranging with a peer both sides already have that the two
     * dial each other at the same moment. Both punching nodes must have it
     * enabled, and so must the node that carries the rendezvous between them.
     *
     * @param serveAsRelay also carry other peers' rendezvous — a few dozen
     *                     forwarded bytes per punch, only ever to peers this node
     *                     already holds. A mesh in which nobody relays cannot
     *                     punch at all.
     */
    public void enableHolePunch(boolean serveAsRelay) {
        check(nativeEnableHolePunch(ptr(), serveAsRelay), "enable hole punching");
    }

    /** Enables hole punching and relays other peers' rendezvous. */
    public void enableHolePunch() {
        enableHolePunch(true);
    }

    /**
     * Tries to reach a peer by punching. Non-blocking: success arrives as an
     * ordinary {@link #onPeerConnected(PeerCallback)}.
     *
     * @throws RatsException with {@link ErrorCode#NOT_ENABLED} if hole punching is
     *         off, or {@link ErrorCode#NO_SUCH_PEER} when there is nothing to do
     *         or nothing to try with — the peer is already connected, a punch to
     *         it is already running, or this node does not yet know an external
     *         endpoint of its own to advertise
     */
    public void punchPeer(String peerId) {
        check(nativePunchPeer(ptr(), peerId), "punch to " + peerId);
    }

    /**
     * Enables relaying: reaching a peer that neither port forwarding nor hole
     * punching could make reachable, by routing the connection through a node both
     * ends are already connected to. Call before start.
     *
     * <p>The peer that comes out is ordinary in every way — the same end-to-end
     * encryption, the same channels — except that {@link #peerTransport(String)}
     * reports it as {@link Transport#RELAY}.</p>
     *
     * @param serveAsRelay also carry OTHER peers' connections. Unlike a hole-punch
     *                     rendezvous this spends real bandwidth on somebody else's
     *                     traffic, so it is off by default; a mesh in which nobody
     *                     serves cannot relay at all.
     */
    public void enableRelay(boolean serveAsRelay) {
        check(nativeEnableRelay(ptr(), serveAsRelay), "enable relaying");
    }

    /** Enables relaying without carrying other peers' connections. */
    public void enableRelay() {
        enableRelay(false);
    }

    /**
     * Tries to reach a peer through a relay. Non-blocking: success arrives as an
     * ordinary {@link #onPeerConnected(PeerCallback)}. Usually unnecessary: with
     * hole punching enabled too, a punch that cannot work hands the target over by
     * itself.
     *
     * @throws RatsException with {@link ErrorCode#NOT_ENABLED} if relaying is off,
     *         or {@link ErrorCode#NO_SUCH_PEER} when there is nothing to do or
     *         nothing to try with — the peer is already connected, an attempt is
     *         already running, it is in cooldown, or this node has no peer that
     *         could carry the connection
     */
    public void connectViaRelay(String peerId) {
        check(nativeConnectViaRelay(ptr(), peerId), "relay to " + peerId);
    }

    /** @return what the mesh has shown about this node's own NAT. */
    public NatMapping natMapping() {
        return NatMapping.fromValue(nativeNatMapping(ptr()));
    }

    // ===================== pub/sub (enable before start) =====================

    /** Enables the pub/sub (GossipSub) subsystem. Call before start. */
    public void enablePubsub() {
        check(nativeEnablePubsub(ptr()), "enable pub/sub");
    }

    /** Subscribes to a topic. Call before start. */
    public void subscribe(String topic, TopicCallback callback) {
        check(nativeSubscribe(ptr(), topic, callback), "subscribe to '" + topic + "'");
    }

    /** Unsubscribes from a topic. */
    public void unsubscribe(String topic) {
        check(nativeUnsubscribe(ptr(), topic), "unsubscribe from '" + topic + "'");
    }

    /** Publishes raw bytes to a topic. */
    public void publish(String topic, byte[] data) {
        check(nativePublish(ptr(), topic, data), "publish to '" + topic + "'");
    }

    // ===================== typed JSON messaging (enable before start) =====================

    /** Enables the typed-JSON messaging subsystem. Call before start. */
    public void enableJson() {
        check(nativeEnableJson(ptr()), "enable JSON messaging");
    }

    /** Registers an additive handler for JSON messages of {@code type}. */
    public void onJson(String type, JsonCallback callback) {
        check(nativeOnJson(ptr(), type, callback), "register JSON handler '" + type + "'");
    }

    /** Like {@link #onJson}, but the handler is removed after it fires once. */
    public void onceJson(String type, JsonCallback callback) {
        check(nativeOnceJson(ptr(), type, callback), "register one-shot JSON handler '" + type + "'");
    }

    /** Removes the handlers for JSON messages of {@code type}. */
    public void offJson(String type) {
        check(nativeOffJson(ptr(), type), "remove JSON handler '" + type + "'");
    }

    /** Sends a typed JSON message to a peer. {@code json} must be valid JSON text. */
    public void sendJson(String peerId, String type, String json) {
        check(nativeSendJson(ptr(), peerId, type, json), "send JSON '" + type + "'");
    }

    /** Broadcasts a typed JSON message. {@code json} must be valid JSON text. */
    public void broadcastJson(String type, String json) {
        check(nativeBroadcastJson(ptr(), type, json), "broadcast JSON '" + type + "'");
    }

    // ===================== file transfer (enable before start) =====================

    /**
     * Enables the file-transfer subsystem. Call before start.
     *
     * @param tempDir directory holding in-progress downloads; null = current dir
     */
    public void enableFileTransfer(String tempDir) {
        check(nativeEnableFileTransfer(ptr(), tempDir), "enable file transfer");
    }

    /** Sets the incoming-offer callback. Call before start. */
    public void onFileOffer(FileOfferCallback callback) {
        check(nativeOnFileOffer(ptr(), callback), "register file-offer callback");
    }

    /** Sets the transfer-progress callback. Call before start. */
    public void onFileProgress(FileProgressCallback callback) {
        check(nativeOnFileProgress(ptr(), callback), "register file-progress callback");
    }

    /** Sets the transfer-complete callback. Call before start. */
    public void onFileComplete(FileCompleteCallback callback) {
        check(nativeOnFileComplete(ptr(), callback), "register file-complete callback");
    }

    /**
     * Offers a file to a peer.
     *
     * @return the transfer id, or 0 if the offer was refused outright (subsystem
     *         off, or unknown peer)
     */
    public long sendFile(String peerId, String path) {
        return nativeSendFile(ptr(), peerId, path);
    }

    /**
     * Offers a directory tree to a peer.
     *
     * @return the transfer id, or 0 if the offer was refused outright
     */
    public long sendDirectory(String peerId, String dirPath) {
        return nativeSendDirectory(ptr(), peerId, dirPath);
    }

    /**
     * Accepts an offered transfer.
     *
     * @param destPath the file path for a single file, else the destination directory
     */
    public void acceptFile(String peerId, long transferId, String destPath) {
        check(nativeAcceptFile(ptr(), peerId, transferId, destPath), "accept transfer " + transferId);
    }

    /** Rejects an offered transfer. */
    public void rejectFile(String peerId, long transferId) {
        check(nativeRejectFile(ptr(), peerId, transferId), "reject transfer " + transferId);
    }

    /** Cancels a live transfer (either side). */
    public void cancelFile(String peerId, long transferId) {
        check(nativeCancelFile(ptr(), peerId, transferId), "cancel transfer " + transferId);
    }

    /** Pauses a live transfer (either side). */
    public void pauseFile(String peerId, long transferId) {
        check(nativePauseFile(ptr(), peerId, transferId), "pause transfer " + transferId);
    }

    /** Resumes a paused transfer (either side). */
    public void resumeFile(String peerId, long transferId) {
        check(nativeResumeFile(ptr(), peerId, transferId), "resume transfer " + transferId);
    }

    // ===================== liveness / reconnection (enable before start) =====================

    /** Enables periodic ping/pong RTT probing of every peer. Call before start. */
    public void enablePing() {
        check(nativeEnablePing(ptr()), "enable ping");
    }

    /**
     * @return the last measured round-trip time to a peer in milliseconds, or -1
     *         if unknown (ping not enabled, or no pong received yet)
     */
    public long peerRttMs(String peerId) {
        return nativePeerRttMs(ptr(), peerId);
    }

    /**
     * Enables the reconnection subsystem: re-dials dropped peers with exponential
     * backoff. Dialed peers are remembered automatically; with a
     * {@link Config#dataDir(String)} set, targets persist across restarts.
     */
    public void enableReconnect() {
        check(nativeEnableReconnect(ptr()), "enable reconnect");
    }

    /** Adds an address to keep connected (re-dialed on drop). */
    public void addReconnect(String host, int port) {
        check(nativeAddReconnect(ptr(), host, port), "add reconnect target " + host + ":" + port);
    }

    /** Stops reconnecting to an address and drops it from the store. */
    public void removeReconnect(String host, int port) {
        check(nativeRemoveReconnect(ptr(), host, port), "remove reconnect target " + host + ":" + port);
    }

    // ===================== process-global helpers =====================

    /** Sets the process-global log verbosity. */
    public static void setLogLevel(LogLevel level) {
        nativeSetLogLevel(level.value());
    }

    /** Mirrors logs to a file; null or empty disables file logging. */
    public static void setLogFile(String path) {
        nativeSetLogFile(path);
    }

    /** @return the library version as a string, e.g. {@code "1.2.3"}. */
    public static String version() {
        return nativeVersionString();
    }

    /** @return the version components as {@code [major, minor, patch, build]}. */
    public static int[] versionInfo() {
        return nativeVersion();
    }

    /** @return git describe of the build, e.g. {@code "v1.2.3-4-gabcdef"}. */
    public static String gitDescribe() {
        return nativeGitDescribe();
    }

    /** @return the packed ABI id, {@code (major << 16) | (minor << 8) | patch}. */
    public static int abi() {
        return nativeAbi();
    }

    // ===================== internals =====================

    /**
     * The native handle, refusing to hand out one that has been released. The C
     * ABI does not null-check its handle, so a call after {@link #close()} would
     * be a crash rather than an exception.
     */
    private long ptr() {
        if (nativePtr == 0) {
            throw new RatsException("This node has been closed");
        }
        return nativePtr;
    }

    /** Turns a non-OK {@code rats_error_t} into a {@link RatsException}. */
    private static void check(int code, String operation) {
        if (code != 0) {
            throw new RatsException(ErrorCode.fromCode(code), operation);
        }
    }

    // ===================== native declarations =====================

    private native long nativeCreateConfig(int listenPort, boolean enableListen, String bindAddress,
                                           int security, String dataDir, String protocol,
                                           long maxPeers, boolean enableTcp, boolean enableUdp,
                                           int preferredTransport, int transportFallbackMs);
    private native void nativeDestroy(long ptr);
    private native int nativeStart(long ptr);
    private native void nativeStop(long ptr);

    private native int nativeListenPort(long ptr);
    private native String nativeLocalId(long ptr);
    private native String nativeProtocol(long ptr);
    private native int nativeTransports(long ptr);

    private native int nativeConnect(long ptr, String host, int port);
    private native long nativePeerCount(long ptr);
    private native String[] nativePeerIds(long ptr);
    private native void nativeSetMaxPeers(long ptr, long maxPeers);
    private native long nativeMaxPeers(long ptr);
    private native int nativePeerTransport(long ptr, String peerId);
    private native int nativePeerTransports(long ptr, String peerId);

    private native int nativeSend(long ptr, String peerId, String channel, byte[] data);
    private native int nativeBroadcast(long ptr, String channel, byte[] data);
    private native boolean nativePeerWritable(long ptr, String peerId);
    private native int nativeOn(long ptr, String channel, MessageCallback callback);

    private native int nativeOnPeerConnected(long ptr, PeerCallback callback);
    private native int nativeOnPeerDisconnected(long ptr, PeerDisconnectCallback callback);
    private native int nativeOnPeerWritable(long ptr, PeerCallback callback);

    private native int nativeEnableDht(long ptr, int dhtPort, String discoveryKey);
    private native int nativeEnableMdns(long ptr);
    private native int nativeEnablePortMapping(long ptr, boolean enableUpnp, boolean enableNatpmp);
    private native int nativeEnableHolePunch(long ptr, boolean serveAsRelay);
    private native int nativePunchPeer(long ptr, String peerId);
    private native int nativeEnableRelay(long ptr, boolean serveAsRelay);
    private native int nativeConnectViaRelay(long ptr, String peerId);
    private native int nativeNatMapping(long ptr);

    private native int nativeEnablePubsub(long ptr);
    private native int nativeSubscribe(long ptr, String topic, TopicCallback callback);
    private native int nativeUnsubscribe(long ptr, String topic);
    private native int nativePublish(long ptr, String topic, byte[] data);

    private native int nativeEnableJson(long ptr);
    private native int nativeOnJson(long ptr, String type, JsonCallback callback);
    private native int nativeOnceJson(long ptr, String type, JsonCallback callback);
    private native int nativeOffJson(long ptr, String type);
    private native int nativeSendJson(long ptr, String peerId, String type, String json);
    private native int nativeBroadcastJson(long ptr, String type, String json);

    private native int nativeEnableFileTransfer(long ptr, String tempDir);
    private native int nativeOnFileOffer(long ptr, FileOfferCallback callback);
    private native int nativeOnFileProgress(long ptr, FileProgressCallback callback);
    private native int nativeOnFileComplete(long ptr, FileCompleteCallback callback);
    private native long nativeSendFile(long ptr, String peerId, String path);
    private native long nativeSendDirectory(long ptr, String peerId, String dirPath);
    private native int nativeAcceptFile(long ptr, String peerId, long transferId, String destPath);
    private native int nativeRejectFile(long ptr, String peerId, long transferId);
    private native int nativeCancelFile(long ptr, String peerId, long transferId);
    private native int nativePauseFile(long ptr, String peerId, long transferId);
    private native int nativeResumeFile(long ptr, String peerId, long transferId);

    private native int nativeEnablePing(long ptr);
    private native long nativePeerRttMs(long ptr, String peerId);

    private native int nativeEnableReconnect(long ptr);
    private native int nativeAddReconnect(long ptr, String host, int port);
    private native int nativeRemoveReconnect(long ptr, String host, int port);

    private static native void nativeSetLogLevel(int level);
    private static native void nativeSetLogFile(String path);
    private static native String nativeVersionString();
    private static native int[] nativeVersion();
    private static native String nativeGitDescribe();
    private static native int nativeAbi();
}
