package com.librats;

import android.util.Log;

import java.util.Collections;
import java.util.Set;

/**
 * One librats node: a Java wrapper over the C ABI
 * ({@code src/librats/bindings/rats.h}).
 *
 * <p>A bare node is encrypted transport (Noise XX over UDP or TCP, both on one
 * port), a self-certifying peer id, dialing, and messages on named channels.
 * Discovery, NAT traversal, pub/sub, JSON messaging, file transfer, ping and
 * reconnection are opt-in: call the matching {@code enable*} method.</p>
 *
 * <p><b>Order.</b> Enable subsystems and register the node's callbacks before
 * {@link #start()}. Afterwards both throw with {@link ErrorCode#ALREADY_STARTED};
 * using a subsystem that was never enabled throws with
 * {@link ErrorCode#NOT_ENABLED}.</p>
 *
 * <p><b>Threads.</b> Every method may be called from any thread. Callbacks run on
 * an internal reactor thread: keep them short, never block in them, and hop to
 * the UI thread before touching views.</p>
 *
 * <p><b>Lifetime.</b> {@link #close()} stops the node and frees it; the callbacks
 * it was given are released with it. Do not close a node while another thread is
 * still calling into it, nor from inside one of its own callbacks (closing waits
 * for the very thread that runs them).</p>
 *
 * <pre>{@code
 * RatsNode node = new RatsNode(new RatsNode.Config()
 *         .listenPort(8080)
 *         .dataDir(getFilesDir().getAbsolutePath()));
 * node.onPeerConnected(id -> Log.i(TAG, "+ " + id));
 * node.on("chat", (id, data) -> Log.i(TAG, new String(data, StandardCharsets.UTF_8)));
 * node.enableMdns();
 * node.start();
 * }</pre>
 */
public class RatsNode implements AutoCloseable {
    private static final String TAG = "RatsNode";

    static {
        try {
            System.loadLibrary("rats_jni");
        } catch (UnsatisfiedLinkError e) {
            Log.e(TAG, "Failed to load librats_jni", e);
            throw e;
        }
    }

    /** Longest lifetime a live message may have; a longer one is cut to this. */
    public static final int LIVE_MAX_LIFETIME_MS = 30000;
    /** Largest payload a live message may carry. */
    public static final int LIVE_MAX_PAYLOAD = 4 * 1024 * 1024;

    /**
     * Node configuration ({@code rats_config_t}). Every setter returns
     * {@code this}; anything left unset is the library default.
     *
     * <pre>{@code
     * new RatsNode.Config().listenPort(8080).protocol("myapp/1.0").maxPeers(50)
     * }</pre>
     */
    public static final class Config {
        /** {@link #transportFallbackMs(int)} value that never races the second transport. */
        public static final int FALLBACK_NEVER = -1;   // RATS_FALLBACK_NEVER as a uint32

        // Read field by field by librats_jni.cpp (nativeCreate); names and types
        // are part of the native contract. Zero means the library default, except
        // for the two booleans that default to on.
        String protocol;
        String dataDir;
        int security;
        int listenPort;
        String bindAddress;
        boolean dialOnly;
        long maxPeers;
        int transports;
        int preferredTransport;
        int transportFallbackMs;
        long sendQueueLimit;
        int pathSampleMs;
        int congestionControl;
        long udpReceiveWindow;
        long udpReceiveBudget;
        boolean udpOffload = true;
        int reactorThreads;
        boolean networkMonitor = true;

        /**
         * App id bound into the handshake, e.g. {@code "myapp/1.0"}; peers with a
         * different one cannot connect. Default {@code "librats/1.0"}.
         */
        public Config protocol(String protocol) {
            this.protocol = protocol;
            return this;
        }

        /**
         * Directory for persistent state: the identity, the DHT routing table, the
         * reconnect list. Unset, the node gets a new identity every run. On Android,
         * {@code context.getFilesDir()}.
         */
        public Config dataDir(String dir) {
            this.dataDir = dir;
            return this;
        }

        /** Default {@link Security#NOISE}. */
        public Config security(Security security) {
            this.security = security.value();
            return this;
        }

        /** Inbound port, shared by both transports. Default 0: ephemeral. */
        public Config listenPort(int port) {
            if (port < 0 || port > 65535) throw new IllegalArgumentException("port " + port);
            this.listenPort = port;
            return this;
        }

        /** Interface to listen on. Default {@code "::"}, dual-stack on every interface. */
        public Config bindAddress(String address) {
            this.bindAddress = address;
            return this;
        }

        /** True: no listener, outbound connections only. Default false. */
        public Config dialOnly(boolean dialOnly) {
            this.dialOnly = dialOnly;
            return this;
        }

        /** Cap on established peers, enforced on inbound. Default 0: unlimited. */
        public Config maxPeers(int maxPeers) {
            this.maxPeers = nonNegative(maxPeers, "maxPeers");
            return this;
        }

        /** Transports to run. Default both. {@link Transport#RELAY} is not one to run. */
        public Config transports(Transport... transports) {
            int mask = 0;
            for (Transport t : transports) {
                if (t == Transport.RELAY) throw new IllegalArgumentException("RELAY is not a transport to run");
                mask |= t.mask();
            }
            this.transports = mask;
            return this;
        }

        /** Transport a dial tries first. Default {@link Transport#UDP}. */
        public Config preferredTransport(Transport transport) {
            if (transport == Transport.RELAY) throw new IllegalArgumentException("a relay is never dialed");
            this.preferredTransport = transport.value();
            return this;
        }

        /**
         * How long the preferred transport dials alone before the other is raced.
         * 0 is the default (1200 ms); {@link #FALLBACK_NEVER} never races it.
         */
        public Config transportFallbackMs(int ms) {
            if (ms < 0 && ms != FALLBACK_NEVER) throw new IllegalArgumentException("transportFallbackMs " + ms);
            this.transportFallbackMs = ms;
            return this;
        }

        /**
         * Bytes a peer's send queue may hold before a sender that keeps going has
         * it dropped ({@link CloseReason#SLOW_CONSUMER}); {@link #peerWritable}
         * turns false at a quarter of it. Not a message size limit. Default 0: 8 MiB.
         */
        public Config sendQueueLimit(long bytes) {
            this.sendQueueLimit = nonNegative(bytes, "sendQueueLimit");
            return this;
        }

        /**
         * How often each peer's path is sampled for {@link #pathStats(String)}.
         * Default 0: only while an {@link #onPeerPath(PathCallback)} callback is
         * registered, every 100 ms.
         */
        public Config pathSampleMs(int ms) {
            this.pathSampleMs = (int) nonNegative(ms, "pathSampleMs");
            return this;
        }

        /** Congestion controller of every UDP connection. Default {@link Congestion#BBR}. */
        public Config congestionControl(Congestion congestion) {
            this.congestionControl = congestion.value();
            return this;
        }

        /**
         * Ceiling one UDP connection's flow-control window grows to (it starts at
         * 1 MiB); throughput is bounded by window / round trip. Default 0: 16 MiB.
         */
        public Config udpReceiveWindow(long bytes) {
            this.udpReceiveWindow = nonNegative(bytes, "udpReceiveWindow");
            return this;
        }

        /** Bytes all UDP connections together may hold out of order. Default 0: 64 MiB. */
        public Config udpReceiveBudget(long bytes) {
            this.udpReceiveBudget = nonNegative(bytes, "udpReceiveBudget");
            return this;
        }

        /** Kernel segmentation offload for UDP where the system has it. Default true. */
        public Config udpOffload(boolean enable) {
            this.udpOffload = enable;
            return this;
        }

        /** I/O threads. Default 0: one, enough for thousands of peers. */
        public Config reactorThreads(int threads) {
            this.reactorThreads = (int) nonNegative(threads, "reactorThreads");
            return this;
        }

        /**
         * Watch the device for interface and address changes and react to them.
         * Costs one mostly idle thread. Default true.
         */
        public Config networkMonitor(boolean enable) {
            this.networkMonitor = enable;
            return this;
        }

        private static long nonNegative(long value, String name) {
            if (value < 0) throw new IllegalArgumentException(name + " must be >= 0, got " + value);
            return value;
        }
    }

    private volatile long nativePtr;
    private final String localId;
    private final String protocol;

    // ===================== construction and lifecycle =====================

    /** A node with every default: listening on an ephemeral port, both transports. */
    public RatsNode() {
        this(new Config());
    }

    /**
     * @throws RatsException if the config is impossible: no transport, or TCP
     *         preferred while it is turned off
     */
    public RatsNode(Config config) {
        nativePtr = nativeCreate(config != null ? config : new Config());
        if (nativePtr == 0) {
            throw new RatsException("Could not create the node: the config is invalid");
        }
        localId = nativeLocalId(nativePtr);
        protocol = nativeProtocol(nativePtr);
    }

    /**
     * Opens the sockets and starts every enabled subsystem.
     *
     * @throws RatsException {@link ErrorCode#BIND} if the port is taken,
     *         {@link ErrorCode#ALREADY_STARTED} if it is running
     */
    public void start() {
        check(nativeStart(ptr()), "start");
    }

    /** Closes every connection and stops. Idempotent. */
    public void stop() {
        long p = nativePtr;
        if (p != 0) nativeStop(p);
    }

    /** Stops the node and frees it. Idempotent; the node is unusable afterwards. */
    @Override
    public synchronized void close() {
        long p = nativePtr;
        if (p != 0) {
            nativePtr = 0;
            nativeDestroy(p);
        }
    }

    /** Last-resort cleanup for a node that was never closed; close it yourself. */
    @Override
    @SuppressWarnings({"deprecation", "removal"})
    protected void finalize() throws Throwable {
        try {
            close();
        } finally {
            super.finalize();
        }
    }

    // ===================== this node =====================

    /** @return our peer id, 64-char lowercase hex. */
    public String localId() {
        return localId;
    }

    /** @return the protocol bound into the handshake. */
    public String protocol() {
        return protocol;
    }

    /** @return the bound listen port (the real one when 0 was asked for); 0 before start. */
    public int listenPort() {
        return nativeListenPort(ptr());
    }

    /**
     * @return the transports actually running; can be narrower than configured (a
     *         UDP socket that cannot be bound leaves the node TCP-only). Empty
     *         when not running.
     */
    public Set<Transport> transports() {
        return Collections.unmodifiableSet(Transport.fromMask(nativeTransports(ptr())));
    }

    /** @return what the mesh has shown about this node's NAT. */
    public NatMapping natMapping() {
        return NatMapping.fromValue(nativeNatMapping(ptr()));
    }

    /** @return our own addresses as peers report seeing us, {@code "ip:port"}; never null. */
    public String[] observedAddresses() {
        return nativeObservedAddresses(ptr());
    }

    // ===================== peers =====================

    /**
     * Dials host:port (a literal or a hostname). Non-blocking: success arrives at
     * {@link #onPeerConnected(PeerCallback)}, failure at
     * {@link #onDialFailed(DialFailedCallback)}.
     *
     * @throws RatsException {@link ErrorCode#NOT_STARTED} before {@link #start()}
     */
    public void connect(String host, int port) {
        check(nativeConnect(ptr(), host, port), "connect to " + host + ":" + port);
    }

    /** Closes the connection to a peer. @throws RatsException {@link ErrorCode#NO_SUCH_PEER} */
    public void disconnect(String peerId) {
        check(nativeDisconnect(ptr(), peerId), "disconnect " + peerId);
    }

    /** @return the number of connected peers. */
    public int peerCount() {
        return (int) nativePeerCount(ptr());
    }

    /** @return the ids of the connected peers; never null. */
    public String[] peerIds() {
        return nativePeerIds(ptr());
    }

    /** @return what is known about a connected peer, or null if it is not connected. */
    public PeerInfo peerInfo(String peerId) {
        PeerInfo[] out = new PeerInfo[1];
        int code = nativePeerInfo(ptr(), peerId, out);
        if (code == ErrorCode.NO_SUCH_PEER.code()) return null;
        check(code, "peer info for " + peerId);
        return out[0];
    }

    /** Caps established peers (0 = unlimited). Can be changed while running. */
    public void setMaxPeers(int maxPeers) {
        if (maxPeers < 0) throw new IllegalArgumentException("maxPeers must be >= 0");
        nativeSetMaxPeers(ptr(), maxPeers);
    }

    /** @return the established-peer cap (0 = unlimited). */
    public int maxPeers() {
        return (int) Math.min(nativeMaxPeers(ptr()), Integer.MAX_VALUE);
    }

    // ===================== messaging =====================

    /** Sends bytes to one peer on a named channel, reliably. */
    public void send(String peerId, String channel, byte[] data) {
        send(peerId, channel, data, 0);
    }

    /**
     * Sends bytes to one peer on a named channel.
     *
     * <p>{@code lifetimeMs} 0 is reliable: the message arrives, in order with
     * everything else this node sends on its channels. Above 0 it is a live
     * message, worth delivering only within that many ms (at most
     * {@link #LIVE_MAX_LIFETIME_MS}): repaired while it can still arrive in time,
     * dropped whole once it cannot, never delivered partly or twice, and ordered
     * with nothing. Made for audio and video frames; at most
     * {@link #LIVE_MAX_PAYLOAD} bytes. The receiver needs nothing special.</p>
     *
     * <p>Returning means queued, not delivered. If you send in bulk, ask
     * {@link #peerWritable(String)} after each send.</p>
     *
     * @throws RatsException {@link ErrorCode#NO_SUCH_PEER}, or
     *         {@link ErrorCode#INVALID_ARG} for a live payload over the limit
     */
    public void send(String peerId, String channel, byte[] data, int lifetimeMs) {
        requireLifetime(lifetimeMs);
        check(nativeSend(ptr(), peerId, channel, data, lifetimeMs), "send on '" + channel + "'");
    }

    /** Sends bytes on a named channel to every connected peer, reliably. */
    public void broadcast(String channel, byte[] data) {
        broadcast(channel, data, 0);
    }

    /** {@link #send(String, String, byte[], int)} to every connected peer. */
    public void broadcast(String channel, byte[] data, int lifetimeMs) {
        requireLifetime(lifetimeMs);
        check(nativeBroadcast(ptr(), channel, data, lifetimeMs), "broadcast on '" + channel + "'");
    }

    /**
     * Whether the peer's send queue has room; false too for a peer that is not
     * connected. False means stop: what you sent was queued, but keep adding and
     * the peer is dropped with {@link CloseReason#SLOW_CONSUMER}. Resume on
     * {@link #onPeerWritable(PeerCallback)}, or poll this from your own thread.
     */
    public boolean peerWritable(String peerId) {
        return nativePeerWritable(ptr(), peerId);
    }

    /**
     * What the transport knows about the path to a peer, for a sender that sizes
     * its output to it. Sampling runs only with {@link Config#pathSampleMs(int)}
     * set or an {@link #onPeerPath(PathCallback)} callback registered.
     *
     * @return the latest sample, or null if the peer is not connected or nothing
     *         was sampled yet
     */
    public PathStats pathStats(String peerId) {
        PathStats[] out = new PathStats[1];
        int code = nativePathStats(ptr(), peerId, out);
        if (code == ErrorCode.NO_SUCH_PEER.code()) return null;
        check(code, "path stats for " + peerId);
        return out[0];
    }

    // ===================== callbacks (before start; several may coexist) =====================

    /** Messages on a named channel. */
    public void on(String channel, MessageCallback callback) {
        check(nativeOn(ptr(), channel, callback), "register handler for '" + channel + "'");
    }

    /** A peer connected. */
    public void onPeerConnected(PeerCallback callback) {
        check(nativeOnPeerConnected(ptr(), callback), "register peer-connected callback");
    }

    /** A peer disconnected, with the reason. */
    public void onPeerDisconnected(PeerDisconnectCallback callback) {
        check(nativeOnPeerDisconnected(ptr(), callback), "register peer-disconnected callback");
    }

    /** A dial to a numeric address failed over every transport tried. */
    public void onDialFailed(DialFailedCallback callback) {
        check(nativeOnDialFailed(ptr(), callback), "register dial-failed callback");
    }

    /** A peer whose send queue had filled drained back under its mark. */
    public void onPeerWritable(PeerCallback callback) {
        check(nativeOnPeerWritable(ptr(), callback), "register peer-writable callback");
    }

    /**
     * A path sample of every connected peer, every {@link Config#pathSampleMs(int)}
     * (100 ms if 0). Registering one turns sampling on.
     */
    public void onPeerPath(PathCallback callback) {
        check(nativeOnPeerPath(ptr(), callback), "register peer-path callback");
    }

    // ===================== discovery (enable before start) =====================

    /**
     * Mainline DHT: announces and searches a key, dialing the peers found.
     *
     * @param dhtPort      0 for an ephemeral port
     * @param discoveryKey null for the node's protocol, so only nodes that could
     *                     handshake find each other
     */
    public void enableDht(int dhtPort, String discoveryKey) {
        check(nativeEnableDht(ptr(), dhtPort, discoveryKey), "enable DHT");
    }

    /** DHT on an ephemeral port, keyed by the protocol. */
    public void enableDht() {
        enableDht(0, null);
    }

    /** mDNS discovery on the local network. */
    public void enableMdns() {
        check(nativeEnableMdns(ptr()), "enable mDNS");
    }

    /**
     * Peer exchange: connected peers trade the addresses of peers they hold, so
     * one contact is enough to find the rest of the mesh.
     */
    public void enablePeerExchange() {
        check(nativeEnablePeerExchange(ptr()), "enable peer exchange");
    }

    // ===================== NAT traversal (enable before start) =====================

    /** Asks the router to forward the listen port, over UPnP IGD and/or NAT-PMP. */
    public void enablePortMapping(boolean upnp, boolean natpmp) {
        check(nativeEnablePortMapping(ptr(), upnp, natpmp), "enable port mapping");
    }

    /** Port mapping over both UPnP IGD and NAT-PMP. */
    public void enablePortMapping() {
        enablePortMapping(true, true);
    }

    /**
     * UDP hole punching: reach a peer behind a NAT by having a peer both sides
     * share arrange for the two to dial each other at the same moment. Every node
     * involved needs it enabled.
     *
     * @param serveRendezvous also pass other peers' rendezvous along — a few dozen
     *                        bytes per punch; a mesh where nobody does cannot punch
     */
    public void enableHolePunch(boolean serveRendezvous) {
        check(nativeEnableHolePunch(ptr(), serveRendezvous), "enable hole punching");
    }

    /** Hole punching, serving other peers' rendezvous too. */
    public void enableHolePunch() {
        enableHolePunch(true);
    }

    /**
     * Starts punching to a peer. Success arrives at
     * {@link #onPeerConnected(PeerCallback)}.
     *
     * @throws RatsException {@link ErrorCode#DECLINED} if already connected,
     *         already punching, or no external endpoint of our own is known yet
     *         (that takes at least one UDP peer)
     */
    public void punchPeer(String peerId) {
        check(nativePunchPeer(ptr(), peerId), "punch to " + peerId);
    }

    /**
     * Relaying: reach a peer nothing else can, through a node both ends are
     * connected to. Encryption stays end to end; {@link #peerInfo(String)} reports
     * {@link Transport#RELAY}. With hole punching enabled too, a punch that cannot
     * work falls back to a relay by itself, and a relayed peer is upgraded to a
     * direct connection when a later punch succeeds.
     *
     * @param serve also carry OTHER peers' connections, which costs this node
     *              their bandwidth
     */
    public void enableRelay(boolean serve) {
        check(nativeEnableRelay(ptr(), serve), "enable relaying");
    }

    /** Relaying for this node's own connections only. */
    public void enableRelay() {
        enableRelay(false);
    }

    /**
     * Starts a relayed connection to a peer. Success arrives at
     * {@link #onPeerConnected(PeerCallback)}.
     *
     * @throws RatsException {@link ErrorCode#DECLINED} if already connected,
     *         already trying or cooling down, or no connected peer can carry it
     */
    public void connectViaRelay(String peerId) {
        check(nativeConnectViaRelay(ptr(), peerId), "relay to " + peerId);
    }

    // ===================== pub/sub =====================

    /** GossipSub pub/sub. Enable before start. */
    public void enablePubsub() {
        check(nativeEnablePubsub(ptr()), "enable pub/sub");
    }

    /** Subscribes to a topic; a second subscribe to the same topic replaces the handler. */
    public void subscribe(String topic, TopicCallback callback) {
        check(nativeSubscribe(ptr(), topic, callback), "subscribe to '" + topic + "'");
    }

    /** Drops the subscription and its handler. */
    public void unsubscribe(String topic) {
        check(nativeUnsubscribe(ptr(), topic), "unsubscribe from '" + topic + "'");
    }

    /** Publishes to every subscriber of the topic. */
    public void publish(String topic, byte[] data) {
        check(nativePublish(ptr(), topic, data), "publish to '" + topic + "'");
    }

    // ===================== JSON messaging =====================

    /** Typed messages carrying a JSON document. Enable before start. */
    public void enableJson() {
        check(nativeEnableJson(ptr()), "enable JSON messaging");
    }

    /** Adds a handler for messages of {@code type}. May be called while running. */
    public void onJson(String type, JsonCallback callback) {
        check(nativeOnJson(ptr(), type, callback), "register JSON handler '" + type + "'");
    }

    /** Like {@link #onJson}; the handler is removed after its first message. */
    public void onceJson(String type, JsonCallback callback) {
        check(nativeOnceJson(ptr(), type, callback), "register one-shot JSON handler '" + type + "'");
    }

    /** Removes every handler of {@code type}. */
    public void offJson(String type) {
        check(nativeOffJson(ptr(), type), "remove JSON handlers '" + type + "'");
    }

    /** @throws RatsException {@link ErrorCode#INVALID_ARG} if {@code json} is not valid JSON */
    public void sendJson(String peerId, String type, String json) {
        check(nativeSendJson(ptr(), peerId, type, json), "send JSON '" + type + "'");
    }

    /** @throws RatsException {@link ErrorCode#INVALID_ARG} if {@code json} is not valid JSON */
    public void broadcastJson(String type, String json) {
        check(nativeBroadcastJson(ptr(), type, json), "broadcast JSON '" + type + "'");
    }

    // ===================== file transfer =====================

    /**
     * File transfer: the sender offers, the receiver accepts. Enable before start.
     *
     * @param tempDir where partial downloads live; null for the working directory
     */
    public void enableFileTransfer(String tempDir) {
        check(nativeEnableFileTransfer(ptr(), tempDir), "enable file transfer");
    }

    /** Sets the offer handler (one; a second call replaces it). Before start. */
    public void onFileOffer(FileOfferCallback callback) {
        check(nativeOnFileOffer(ptr(), callback), "register file-offer callback");
    }

    /** Sets the progress handler (one; a second call replaces it). Before start. */
    public void onFileProgress(FileProgressCallback callback) {
        check(nativeOnFileProgress(ptr(), callback), "register file-progress callback");
    }

    /** Sets the completion handler (one; a second call replaces it). Before start. */
    public void onFileComplete(FileCompleteCallback callback) {
        check(nativeOnFileComplete(ptr(), callback), "register file-complete callback");
    }

    /**
     * Offers a file to a connected peer.
     *
     * @return the transfer id
     * @throws RatsException {@link ErrorCode#NO_SUCH_PEER} if the peer is not
     *         connected, {@link ErrorCode#NOT_FOUND} if the file cannot be read
     */
    public long sendFile(String peerId, String path) {
        long[] id = new long[1];
        check(nativeSendFile(ptr(), peerId, path, id), "send file");
        return id[0];
    }

    /** Offers a directory tree; returns and throws as {@link #sendFile}. */
    public long sendDirectory(String peerId, String path) {
        long[] id = new long[1];
        check(nativeSendDirectory(ptr(), peerId, path, id), "send directory");
        return id[0];
    }

    /**
     * Accepts an offer.
     *
     * @param destPath the file to write for a file, the directory to fill for a directory
     */
    public void acceptFile(String peerId, long transferId, String destPath) {
        check(nativeAcceptFile(ptr(), peerId, transferId, destPath), "accept transfer " + transferId);
    }

    /** Declines an offer. */
    public void rejectFile(String peerId, long transferId) {
        check(nativeRejectFile(ptr(), peerId, transferId), "reject transfer " + transferId);
    }

    /** From either side. @throws RatsException {@link ErrorCode#NOT_FOUND} for no such transfer */
    public void cancelFile(String peerId, long transferId) {
        check(nativeCancelFile(ptr(), peerId, transferId), "cancel transfer " + transferId);
    }

    /** From either side. @throws RatsException {@link ErrorCode#NOT_FOUND} for no such transfer */
    public void pauseFile(String peerId, long transferId) {
        check(nativePauseFile(ptr(), peerId, transferId), "pause transfer " + transferId);
    }

    /** From either side. @throws RatsException {@link ErrorCode#NOT_FOUND} for no such transfer */
    public void resumeFile(String peerId, long transferId) {
        check(nativeResumeFile(ptr(), peerId, transferId), "resume transfer " + transferId);
    }

    // ===================== ping and reconnection =====================

    /** Round-trip probing of every peer. Enable before start. */
    public void enablePing() {
        check(nativeEnablePing(ptr()), "enable ping");
    }

    /** @return the last round trip to a peer in ms, or -1 if unknown */
    public long peerRttMs(String peerId) {
        return nativePeerRttMs(ptr(), peerId);
    }

    /**
     * Redials dropped peers with exponential backoff. Every address dialed is
     * remembered; with {@link Config#dataDir(String)} the list survives restarts.
     * Enable before start — without it a node never redials on its own.
     */
    public void enableReconnect() {
        check(nativeEnableReconnect(ptr()), "enable reconnect");
    }

    /** Keeps an address connected. May be called while running. */
    public void addReconnect(String host, int port) {
        check(nativeAddReconnect(ptr(), host, port), "add reconnect target " + host + ":" + port);
    }

    /** Stops keeping an address connected and forgets it. */
    public void removeReconnect(String host, int port) {
        check(nativeRemoveReconnect(ptr(), host, port), "remove reconnect target " + host + ":" + port);
    }

    // ===================== process-wide =====================

    /** Sets the process-wide log verbosity. */
    public static void setLogLevel(LogLevel level) {
        nativeSetLogLevel(level.value());
    }

    /** Also writes logs to {@code path}; null or empty stops file logging. */
    public static void setLogFile(String path) {
        nativeSetLogFile(path);
    }

    /** @return the library version, e.g. {@code "1.2.3"} */
    public static String version() {
        return nativeVersionString();
    }

    /** @return {@code [major, minor, patch, build]} */
    public static int[] versionInfo() {
        return nativeVersion();
    }

    /** @return {@code git describe} of the build */
    public static String gitDescribe() {
        return nativeGitDescribe();
    }

    /** @return {@code (major << 16) | (minor << 8) | patch} */
    public static int abi() {
        return nativeAbi();
    }

    // ===================== internals =====================

    /** The native handle; the C ABI does not check it, so a closed node must fail here. */
    private long ptr() {
        long p = nativePtr;
        if (p == 0) throw new RatsException("This node has been closed");
        return p;
    }

    private static void check(int code, String operation) {
        if (code != 0) throw new RatsException(ErrorCode.fromCode(code), operation);
    }

    private static void requireLifetime(int lifetimeMs) {
        if (lifetimeMs < 0) throw new IllegalArgumentException("lifetimeMs must be >= 0, got " + lifetimeMs);
    }

    @Override
    public String toString() {
        return "RatsNode{" + localId + (nativePtr == 0 ? ", closed" : "") + "}";
    }

    // ===================== native =====================

    private static native long nativeCreate(Config config);
    private static native void nativeDestroy(long ptr);
    private static native int nativeStart(long ptr);
    private static native void nativeStop(long ptr);

    private static native String nativeLocalId(long ptr);
    private static native String nativeProtocol(long ptr);
    private static native int nativeListenPort(long ptr);
    private static native int nativeTransports(long ptr);
    private static native int nativeNatMapping(long ptr);
    private static native String[] nativeObservedAddresses(long ptr);

    private static native int nativeConnect(long ptr, String host, int port);
    private static native int nativeDisconnect(long ptr, String peerId);
    private static native long nativePeerCount(long ptr);
    private static native String[] nativePeerIds(long ptr);
    private static native int nativePeerInfo(long ptr, String peerId, PeerInfo[] out);
    private static native void nativeSetMaxPeers(long ptr, long maxPeers);
    private static native long nativeMaxPeers(long ptr);

    private static native int nativeSend(long ptr, String peerId, String channel, byte[] data, int lifetimeMs);
    private static native int nativeBroadcast(long ptr, String channel, byte[] data, int lifetimeMs);
    private static native boolean nativePeerWritable(long ptr, String peerId);
    private static native int nativePathStats(long ptr, String peerId, PathStats[] out);

    private static native int nativeOn(long ptr, String channel, MessageCallback callback);
    private static native int nativeOnPeerConnected(long ptr, PeerCallback callback);
    private static native int nativeOnPeerDisconnected(long ptr, PeerDisconnectCallback callback);
    private static native int nativeOnDialFailed(long ptr, DialFailedCallback callback);
    private static native int nativeOnPeerWritable(long ptr, PeerCallback callback);
    private static native int nativeOnPeerPath(long ptr, PathCallback callback);

    private static native int nativeEnableDht(long ptr, int dhtPort, String discoveryKey);
    private static native int nativeEnableMdns(long ptr);
    private static native int nativeEnablePeerExchange(long ptr);

    private static native int nativeEnablePortMapping(long ptr, boolean upnp, boolean natpmp);
    private static native int nativeEnableHolePunch(long ptr, boolean serveRendezvous);
    private static native int nativePunchPeer(long ptr, String peerId);
    private static native int nativeEnableRelay(long ptr, boolean serve);
    private static native int nativeConnectViaRelay(long ptr, String peerId);

    private static native int nativeEnablePubsub(long ptr);
    private static native int nativeSubscribe(long ptr, String topic, TopicCallback callback);
    private static native int nativeUnsubscribe(long ptr, String topic);
    private static native int nativePublish(long ptr, String topic, byte[] data);

    private static native int nativeEnableJson(long ptr);
    private static native int nativeOnJson(long ptr, String type, JsonCallback callback);
    private static native int nativeOnceJson(long ptr, String type, JsonCallback callback);
    private static native int nativeOffJson(long ptr, String type);
    private static native int nativeSendJson(long ptr, String peerId, String type, String json);
    private static native int nativeBroadcastJson(long ptr, String type, String json);

    private static native int nativeEnableFileTransfer(long ptr, String tempDir);
    private static native int nativeOnFileOffer(long ptr, FileOfferCallback callback);
    private static native int nativeOnFileProgress(long ptr, FileProgressCallback callback);
    private static native int nativeOnFileComplete(long ptr, FileCompleteCallback callback);
    private static native int nativeSendFile(long ptr, String peerId, String path, long[] transferId);
    private static native int nativeSendDirectory(long ptr, String peerId, String path, long[] transferId);
    private static native int nativeAcceptFile(long ptr, String peerId, long transferId, String destPath);
    private static native int nativeRejectFile(long ptr, String peerId, long transferId);
    private static native int nativeCancelFile(long ptr, String peerId, long transferId);
    private static native int nativePauseFile(long ptr, String peerId, long transferId);
    private static native int nativeResumeFile(long ptr, String peerId, long transferId);

    private static native int nativeEnablePing(long ptr);
    private static native long nativePeerRttMs(long ptr, String peerId);
    private static native int nativeEnableReconnect(long ptr);
    private static native int nativeAddReconnect(long ptr, String host, int port);
    private static native int nativeRemoveReconnect(long ptr, String host, int port);

    private static native void nativeSetLogLevel(int level);
    private static native void nativeSetLogFile(String path);
    private static native String nativeVersionString();
    private static native int[] nativeVersion();
    private static native String nativeGitDescribe();
    private static native int nativeAbi();
}
