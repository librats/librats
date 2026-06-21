package com.librats;

import android.util.Log;

/**
 * High-level Java wrapper over the librats C ABI ({@code src/bindings/rats.h}).
 *
 * <p>A {@code RatsClient} wraps a native {@code rats_t} node. The model is
 * peer-id-centric: peers are identified by 64-char lowercase hex ids, messages
 * flow over named channels (raw bytes), typed JSON message types, or pub/sub
 * topics.</p>
 *
 * <p><b>Ordering matters.</b> Register callbacks and enable subsystems
 * (DHT, mDNS, pub/sub, JSON, file transfer, ping, reconnect) <em>before</em>
 * calling {@link #start()}. Enabling a subsystem after start throws
 * {@link RatsException} with code {@link #ERR_ALREADY_STARTED}; using a
 * subsystem before enabling it returns {@link #ERR_NOT_ENABLED}.</p>
 *
 * <p>Callbacks fire on an internal reactor thread — do not block in them and
 * marshal to the UI thread (e.g. {@code runOnUiThread}) before touching views.</p>
 */
public class RatsClient {
    private static final String TAG = "RatsClient";

    static {
        try {
            System.loadLibrary("rats_jni");
        } catch (UnsatisfiedLinkError e) {
            Log.e(TAG, "Failed to load native library", e);
            throw e;
        }
    }

    // rats_error_t values (must match src/bindings/rats.h).
    public static final int OK = 0;
    public static final int ERR_INVALID_ARG = 1;
    public static final int ERR_NOT_STARTED = 2;
    public static final int ERR_ALREADY_STARTED = 3;
    public static final int ERR_NOT_ENABLED = 4;
    public static final int ERR_NO_SUCH_PEER = 5;
    public static final int ERR_BIND = 6;
    public static final int ERR_INTERNAL = 7;

    // rats_security_t values.
    public static final int SECURITY_NOISE = 0;
    public static final int SECURITY_PLAINTEXT = 1;

    // rats_log_level_t values.
    public static final int LOG_DEBUG = 0;
    public static final int LOG_INFO = 1;
    public static final int LOG_WARN = 2;
    public static final int LOG_ERROR = 3;

    private long nativePtr = 0;

    /**
     * Full node configuration, mirroring {@code rats_config_t}. Obtain a
     * defaults instance and mutate the fields you care about, then pass to
     * {@link RatsClient#RatsClient(Config)}.
     */
    public static final class Config {
        /** Inbound listen port; 0 = ephemeral. */
        public int listenPort = 0;
        /** false makes a dial-only node (no listener). */
        public boolean enableListen = true;
        /** Bind address; null selects the dual-stack wildcard "::". */
        public String bindAddress = null;
        /** {@link #SECURITY_NOISE} (default) or {@link #SECURITY_PLAINTEXT}. */
        public int security = SECURITY_NOISE;
        /** Persistent state dir; null/"" gives an ephemeral identity per run. */
        public String dataDir = null;
        /** Handshake app namespace; null selects "librats". */
        public String protocolName = null;
        /** Handshake app version; null selects "1.0". */
        public String protocolVersion = null;
        /** Established-peer cap; 0 = unlimited. */
        public long maxPeers = 0;
    }

    /**
     * Creates a listening node on the given port (Noise, dual-stack, ephemeral
     * identity).
     *
     * @param listenPort inbound port, or 0 for an ephemeral port
     */
    public RatsClient(int listenPort) {
        nativePtr = nativeCreate(listenPort);
        if (nativePtr == 0) {
            throw new RatsException("Failed to create native rats node");
        }
    }

    /**
     * Creates a node from a full {@link Config}.
     *
     * @param config the configuration (null selects all defaults)
     */
    public RatsClient(Config config) {
        if (config == null) config = new Config();
        nativePtr = nativeCreateConfig(
                config.listenPort,
                config.enableListen,
                config.bindAddress,
                config.security,
                config.dataDir,
                config.protocolName,
                config.protocolVersion,
                config.maxPeers);
        if (nativePtr == 0) {
            throw new RatsException("Failed to create native rats node");
        }
    }

    // ===================== lifecycle =====================

    /**
     * Starts the node: binds the listener and brings up enabled subsystems.
     *
     * @return {@link #OK} on success, otherwise a {@code rats_error_t} code
     *         ({@link #ERR_ALREADY_STARTED}, {@link #ERR_BIND}).
     */
    public int start() {
        return nativeStart(nativePtr);
    }

    /** Stops the node and closes all connections. */
    public void stop() {
        if (nativePtr != 0) nativeStop(nativePtr);
    }

    /** Destroys the node and releases all native resources. */
    public void destroy() {
        if (nativePtr != 0) {
            nativeDestroy(nativePtr);
            nativePtr = 0;
        }
    }

    @Override
    protected void finalize() throws Throwable {
        destroy();
        super.finalize();
    }

    // ===================== identity / info =====================

    /** @return the port the node is listening on. */
    public int getListenPort() {
        return nativeListenPort(nativePtr);
    }

    /** @return our self-certifying peer id as 64-char lowercase hex. */
    public String getLocalId() {
        return nativeLocalId(nativePtr);
    }

    /** @return the application protocol name bound into the handshake. */
    public String getProtocolName() {
        return nativeProtocolName(nativePtr);
    }

    /** @return the application protocol version bound into the handshake. */
    public String getProtocolVersion() {
        return nativeProtocolVersion(nativePtr);
    }

    // ===================== connections =====================

    /**
     * Dials a peer at host:port.
     *
     * @return {@link #OK} on success, otherwise a {@code rats_error_t} code.
     */
    public int connect(String host, int port) {
        return nativeConnect(nativePtr, host, port);
    }

    /** @return the number of currently-connected peers. */
    public int getPeerCount() {
        return (int) nativePeerCount(nativePtr);
    }

    /** @return hex ids of currently-connected peers (never null). */
    public String[] getPeerIds() {
        String[] ids = nativePeerIds(nativePtr);
        return ids != null ? ids : new String[0];
    }

    /** Caps established peers (0 = unlimited). May be called before or after start. */
    public void setMaxPeers(long maxPeers) {
        nativeSetMaxPeers(nativePtr, maxPeers);
    }

    /** @return the current established-peer cap (0 = unlimited). */
    public long getMaxPeers() {
        return nativeMaxPeers(nativePtr);
    }

    // ===================== messaging (named channel, raw bytes) =====================

    /**
     * Sends raw bytes to a specific peer over a named channel.
     *
     * @return {@link #OK} on success, otherwise a {@code rats_error_t} code.
     */
    public int send(String peerId, String channel, byte[] data) {
        return nativeSend(nativePtr, peerId, channel, data);
    }

    /**
     * Broadcasts raw bytes to all connected peers over a named channel.
     *
     * @return {@link #OK} on success, otherwise a {@code rats_error_t} code.
     */
    public int broadcast(String channel, byte[] data) {
        return nativeBroadcast(nativePtr, channel, data);
    }

    /**
     * Registers a handler for raw messages on a channel. Call before start.
     *
     * @return {@link #OK} on success, otherwise a {@code rats_error_t} code.
     */
    public int on(String channel, MessageCallback callback) {
        return nativeOn(nativePtr, channel, callback);
    }

    // ===================== peer callbacks =====================

    /** Sets the peer-connected callback. Call before start. */
    public int setConnectionCallback(ConnectionCallback callback) {
        return nativeOnPeerConnected(nativePtr, callback);
    }

    /** Sets the peer-disconnected callback. Call before start. */
    public int setDisconnectCallback(DisconnectCallback callback) {
        return nativeOnPeerDisconnected(nativePtr, callback);
    }

    // ===================== discovery / NAT subsystems =====================

    /**
     * Enables DHT discovery. Call before start.
     *
     * @param dhtPort      DHT port (0 = ephemeral)
     * @param discoveryKey app namespace key (null = default)
     */
    public int enableDht(int dhtPort, String discoveryKey) {
        return nativeEnableDht(nativePtr, dhtPort, discoveryKey);
    }

    /** Enables DHT discovery with default port and key. */
    public int enableDht() {
        return enableDht(0, null);
    }

    /** Enables local-network mDNS discovery. Call before start. */
    public int enableMdns() {
        return nativeEnableMdns(nativePtr);
    }

    /**
     * Enables automatic NAT port forwarding for the listen port. Call before start.
     *
     * @param enableUpnp   enable the UPnP IGD backend
     * @param enableNatpmp enable the NAT-PMP backend
     */
    public int enablePortMapping(boolean enableUpnp, boolean enableNatpmp) {
        return nativeEnablePortMapping(nativePtr, enableUpnp, enableNatpmp);
    }

    // ===================== pub/sub (topics, raw bytes) =====================

    /** Enables the pub/sub (GossipSub) subsystem. Call before start. */
    public int enablePubsub() {
        return nativeEnablePubsub(nativePtr);
    }

    /** Subscribes to a topic; matching messages invoke the callback. Call before start. */
    public int subscribe(String topic, TopicMessageCallback callback) {
        return nativeSubscribe(nativePtr, topic, callback);
    }

    /** Unsubscribes from a topic. */
    public int unsubscribe(String topic) {
        return nativeUnsubscribe(nativePtr, topic);
    }

    /** Publishes raw bytes to a topic. */
    public int publish(String topic, byte[] data) {
        return nativePublish(nativePtr, topic, data);
    }

    // ===================== typed JSON messaging =====================

    /** Enables the typed-JSON messaging subsystem. Call before start. */
    public int enableJson() {
        return nativeEnableJson(nativePtr);
    }

    /** Registers a handler for JSON messages of {@code type}. Additive. */
    public int onJson(String type, JsonMessageCallback callback) {
        return nativeOnJson(nativePtr, type, callback);
    }

    /** Like {@link #onJson} but removes the handler after it fires once. */
    public int onceJson(String type, JsonMessageCallback callback) {
        return nativeOnceJson(nativePtr, type, callback);
    }

    /** Removes the handler(s) for JSON messages of {@code type}. */
    public int offJson(String type) {
        return nativeOffJson(nativePtr, type);
    }

    /** Sends a typed JSON message to a peer. {@code json} must be valid JSON text. */
    public int sendJson(String peerId, String type, String json) {
        return nativeSendJson(nativePtr, peerId, type, json);
    }

    /** Broadcasts a typed JSON message. {@code json} must be valid JSON text. */
    public int broadcastJson(String type, String json) {
        return nativeBroadcastJson(nativePtr, type, json);
    }

    // ===================== file transfer =====================

    /**
     * Enables the file-transfer subsystem. Call before start.
     *
     * @param tempDir directory for in-progress downloads (null = current dir)
     */
    public int enableFileTransfer(String tempDir) {
        return nativeEnableFileTransfer(nativePtr, tempDir);
    }

    /** Sets the incoming-offer callback. Call before start. */
    public int setFileOfferCallback(FileOfferCallback callback) {
        return nativeOnFileOffer(nativePtr, callback);
    }

    /** Sets the transfer-progress callback. Call before start. */
    public int setFileProgressCallback(FileProgressCallback callback) {
        return nativeOnFileProgress(nativePtr, callback);
    }

    /** Sets the transfer-complete callback. Call before start. */
    public int setFileCompleteCallback(FileCompleteCallback callback) {
        return nativeOnFileComplete(nativePtr, callback);
    }

    /**
     * Offers a file to a peer.
     *
     * @return the transfer id, or 0 on failure.
     */
    public long sendFile(String peerId, String path) {
        return nativeSendFile(nativePtr, peerId, path);
    }

    /**
     * Offers a directory tree to a peer.
     *
     * @return the transfer id, or 0 on failure.
     */
    public long sendDirectory(String peerId, String dirPath) {
        return nativeSendDirectory(nativePtr, peerId, dirPath);
    }

    /**
     * Accepts an offered transfer. For a single file {@code destPath} is the
     * file path; for a directory it is the destination directory.
     */
    public int acceptFile(String peerId, long transferId, String destPath) {
        return nativeAcceptFile(nativePtr, peerId, transferId, destPath);
    }

    /** Rejects an offered transfer. */
    public int rejectFile(String peerId, long transferId) {
        return nativeRejectFile(nativePtr, peerId, transferId);
    }

    /** Cancels a live transfer (either side). */
    public int cancelFile(String peerId, long transferId) {
        return nativeCancelFile(nativePtr, peerId, transferId);
    }

    /** Pauses a live transfer (either side). */
    public int pauseFile(String peerId, long transferId) {
        return nativePauseFile(nativePtr, peerId, transferId);
    }

    /** Resumes a paused transfer (either side). */
    public int resumeFile(String peerId, long transferId) {
        return nativeResumeFile(nativePtr, peerId, transferId);
    }

    // ===================== liveness (ping/RTT) =====================

    /** Enables periodic ping/pong RTT probing of every peer. Call before start. */
    public int enablePing() {
        return nativeEnablePing(nativePtr);
    }

    /**
     * @return last measured round-trip time to a peer in milliseconds, or -1 if
     *         unknown (ping not enabled, or no pong yet).
     */
    public long getPeerRttMs(String peerId) {
        return nativePeerRttMs(nativePtr, peerId);
    }

    // ===================== automatic reconnection =====================

    /** Enables the reconnection subsystem (re-dials dropped peers). Call before start. */
    public int enableReconnect() {
        return nativeEnableReconnect(nativePtr);
    }

    /** Adds an address to keep connected (re-dialed on drop). */
    public int addReconnect(String host, int port) {
        return nativeAddReconnect(nativePtr, host, port);
    }

    /** Stops reconnecting to an address and drops it from the store. */
    public int removeReconnect(String host, int port) {
        return nativeRemoveReconnect(nativePtr, host, port);
    }

    // ===================== static: logging =====================

    /** Sets the process-global log level (one of {@code LOG_*}). */
    public static void setLogLevel(int level) {
        nativeSetLogLevel(level);
    }

    /** Mirrors logs to a file (null/empty disables file logging). */
    public static void setLogFile(String path) {
        nativeSetLogFile(path);
    }

    // ===================== static: library info =====================

    /** @return library version as a string, e.g. "1.2.3". */
    public static String getVersionString() {
        return nativeVersionString();
    }

    /** @return [major, minor, patch, build]. */
    public static int[] getVersion() {
        return nativeVersion();
    }

    /** @return git describe of the build, e.g. "v1.2.3-4-gabcdef". */
    public static String getGitDescribe() {
        return nativeGitDescribe();
    }

    /** @return packed ABI id as (major&lt;&lt;16)|(minor&lt;&lt;8)|patch. */
    public static int getAbi() {
        return nativeAbi();
    }

    /** @return static human-readable name of a {@code rats_error_t} value. */
    public static String errorString(int error) {
        return nativeErrorStr(error);
    }

    // ===================== native declarations =====================

    private native long nativeCreate(int listenPort);
    private native long nativeCreateConfig(int listenPort, boolean enableListen, String bindAddress,
                                           int security, String dataDir, String protocolName,
                                           String protocolVersion, long maxPeers);
    private native void nativeDestroy(long ptr);
    private native int nativeStart(long ptr);
    private native void nativeStop(long ptr);

    private native int nativeListenPort(long ptr);
    private native String nativeLocalId(long ptr);
    private native String nativeProtocolName(long ptr);
    private native String nativeProtocolVersion(long ptr);

    private native int nativeConnect(long ptr, String host, int port);
    private native long nativePeerCount(long ptr);
    private native String[] nativePeerIds(long ptr);
    private native void nativeSetMaxPeers(long ptr, long maxPeers);
    private native long nativeMaxPeers(long ptr);

    private native int nativeSend(long ptr, String peerId, String channel, byte[] data);
    private native int nativeBroadcast(long ptr, String channel, byte[] data);
    private native int nativeOn(long ptr, String channel, MessageCallback callback);

    private native int nativeOnPeerConnected(long ptr, ConnectionCallback callback);
    private native int nativeOnPeerDisconnected(long ptr, DisconnectCallback callback);

    private native int nativeEnableDht(long ptr, int dhtPort, String discoveryKey);
    private native int nativeEnableMdns(long ptr);
    private native int nativeEnablePortMapping(long ptr, boolean enableUpnp, boolean enableNatpmp);

    private native int nativeEnablePubsub(long ptr);
    private native int nativeSubscribe(long ptr, String topic, TopicMessageCallback callback);
    private native int nativeUnsubscribe(long ptr, String topic);
    private native int nativePublish(long ptr, String topic, byte[] data);

    private native int nativeEnableJson(long ptr);
    private native int nativeOnJson(long ptr, String type, JsonMessageCallback callback);
    private native int nativeOnceJson(long ptr, String type, JsonMessageCallback callback);
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
    private static native String nativeErrorStr(int error);
}
