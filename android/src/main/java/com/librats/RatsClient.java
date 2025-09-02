package com.librats;

import android.util.Log;

/**
 * LibRats Android client wrapper providing peer-to-peer networking capabilities.
 * 
 * This class provides a Java interface to the native LibRats C library,
 * enabling Android applications to participate in peer-to-peer networks
 * with features like direct connections, NAT traversal, encryption, 
 * file transfer, and service discovery.
 */
public class RatsClient {
    private static final String TAG = "RatsClient";
    
    static {
        try {
            System.loadLibrary("rats");
            System.loadLibrary("rats_jni");
        } catch (UnsatisfiedLinkError e) {
            Log.e(TAG, "Failed to load native library", e);
            throw e;
        }
    }
    
    private long nativeClientPtr = 0;
    
    // Connection strategies
    public static final int STRATEGY_DIRECT_ONLY = 0;
    public static final int STRATEGY_STUN_ASSISTED = 1;
    public static final int STRATEGY_ICE_FULL = 2;
    public static final int STRATEGY_TURN_RELAY = 3;
    public static final int STRATEGY_AUTO_ADAPTIVE = 4;
    
    // Error codes
    public static final int SUCCESS = 0;
    public static final int ERROR_INVALID_HANDLE = -1;
    public static final int ERROR_INVALID_PARAMETER = -2;
    public static final int ERROR_NOT_RUNNING = -3;
    public static final int ERROR_OPERATION_FAILED = -4;
    public static final int ERROR_PEER_NOT_FOUND = -5;
    public static final int ERROR_MEMORY_ALLOCATION = -6;
    public static final int ERROR_JSON_PARSE = -7;
    
    /**
     * Creates a new RatsClient instance.
     * 
     * @param listenPort The port to listen on for incoming connections (0 for automatic)
     */
    public RatsClient(int listenPort) {
        nativeClientPtr = nativeCreate(listenPort);
        if (nativeClientPtr == 0) {
            throw new RuntimeException("Failed to create native RatsClient");
        }
    }
    
    /**
     * Starts the client and begins listening for connections.
     * 
     * @return SUCCESS on success, error code on failure
     */
    public int start() {
        return nativeStart(nativeClientPtr);
    }
    
    /**
     * Stops the client and closes all connections.
     */
    public void stop() {
        if (nativeClientPtr != 0) {
            nativeStop(nativeClientPtr);
        }
    }
    
    /**
     * Destroys the client and releases all resources.
     * This should be called when the client is no longer needed.
     */
    public void destroy() {
        if (nativeClientPtr != 0) {
            nativeDestroy(nativeClientPtr);
            nativeClientPtr = 0;
        }
    }
    
    @Override
    protected void finalize() throws Throwable {
        destroy();
        super.finalize();
    }
    
    /**
     * Connects to a peer using the default strategy.
     * 
     * @param host The hostname or IP address of the peer
     * @param port The port number of the peer
     * @return 1 on success, 0 on failure
     */
    public int connect(String host, int port) {
        return nativeConnect(nativeClientPtr, host, port);
    }
    
    /**
     * Connects to a peer using a specific connection strategy.
     * 
     * @param host The hostname or IP address of the peer
     * @param port The port number of the peer
     * @param strategy The connection strategy to use (STRATEGY_*)
     * @return SUCCESS on success, error code on failure
     */
    public int connectWithStrategy(String host, int port, int strategy) {
        return nativeConnectWithStrategy(nativeClientPtr, host, port, strategy);
    }
    
    /**
     * Sends a string message to a specific peer.
     * 
     * @param peerId The ID of the target peer
     * @param message The message to send
     * @return SUCCESS on success, error code on failure
     */
    public int sendString(String peerId, String message) {
        return nativeSendString(nativeClientPtr, peerId, message);
    }
    
    /**
     * Broadcasts a string message to all connected peers.
     * 
     * @param message The message to broadcast
     * @return Number of peers the message was sent to
     */
    public int broadcastString(String message) {
        return nativeBroadcastString(nativeClientPtr, message);
    }
    
    /**
     * Sends binary data to a specific peer.
     * 
     * @param peerId The ID of the target peer
     * @param data The binary data to send
     * @return SUCCESS on success, error code on failure
     */
    public int sendBinary(String peerId, byte[] data) {
        return nativeSendBinary(nativeClientPtr, peerId, data);
    }
    
    /**
     * Broadcasts binary data to all connected peers.
     * 
     * @param data The binary data to broadcast
     * @return Number of peers the data was sent to
     */
    public int broadcastBinary(byte[] data) {
        return nativeBroadcastBinary(nativeClientPtr, data);
    }
    
    /**
     * Sends a JSON message to a specific peer.
     * 
     * @param peerId The ID of the target peer
     * @param jsonStr The JSON string to send
     * @return SUCCESS on success, error code on failure
     */
    public int sendJson(String peerId, String jsonStr) {
        return nativeSendJson(nativeClientPtr, peerId, jsonStr);
    }
    
    /**
     * Broadcasts a JSON message to all connected peers.
     * 
     * @param jsonStr The JSON string to broadcast
     * @return Number of peers the message was sent to
     */
    public int broadcastJson(String jsonStr) {
        return nativeBroadcastJson(nativeClientPtr, jsonStr);
    }
    
    /**
     * Gets the number of currently connected peers.
     * 
     * @return The number of connected peers
     */
    public int getPeerCount() {
        return nativeGetPeerCount(nativeClientPtr);
    }
    
    /**
     * Gets this client's peer ID.
     * 
     * @return The peer ID string
     */
    public String getOurPeerId() {
        return nativeGetOurPeerId(nativeClientPtr);
    }
    
    /**
     * Gets connection statistics as a JSON string.
     * 
     * @return JSON string containing connection statistics
     */
    public String getConnectionStatisticsJson() {
        return nativeGetConnectionStatisticsJson(nativeClientPtr);
    }
    
    /**
     * Gets the IDs of all connected peers.
     * 
     * @return Array of peer ID strings
     */
    public String[] getPeerIds() {
        return nativeGetPeerIds(nativeClientPtr);
    }
    
    /**
     * Enables or disables encryption for this client.
     * 
     * @param enabled true to enable encryption, false to disable
     * @return SUCCESS on success, error code on failure
     */
    public int setEncryptionEnabled(boolean enabled) {
        return nativeSetEncryptionEnabled(nativeClientPtr, enabled);
    }
    
    /**
     * Checks if encryption is enabled for this client.
     * 
     * @return true if encryption is enabled, false otherwise
     */
    public boolean isEncryptionEnabled() {
        return nativeIsEncryptionEnabled(nativeClientPtr);
    }
    
    /**
     * Generates a new encryption key for this client.
     * 
     * @return The generated encryption key as a hex string
     */
    public String generateEncryptionKey() {
        return nativeGenerateEncryptionKey(nativeClientPtr);
    }
    
    /**
     * Sets the encryption key for this client.
     * 
     * @param key The encryption key as a hex string
     * @return SUCCESS on success, error code on failure
     */
    public int setEncryptionKey(String key) {
        return nativeSetEncryptionKey(nativeClientPtr, key);
    }
    
    /**
     * Starts DHT discovery on the specified port.
     * 
     * @param dhtPort The port to use for DHT discovery
     * @return SUCCESS on success, error code on failure
     */
    public int startDhtDiscovery(int dhtPort) {
        return nativeStartDhtDiscovery(nativeClientPtr, dhtPort);
    }
    
    /**
     * Stops DHT discovery.
     */
    public void stopDhtDiscovery() {
        nativeStopDhtDiscovery(nativeClientPtr);
    }
    
    /**
     * Checks if DHT discovery is running.
     * 
     * @return true if DHT is running, false otherwise
     */
    public boolean isDhtRunning() {
        return nativeIsDhtRunning(nativeClientPtr);
    }
    
    /**
     * Starts mDNS discovery with the specified service name.
     * 
     * @param serviceName The service name to advertise/discover
     * @return SUCCESS on success, error code on failure
     */
    public int startMdnsDiscovery(String serviceName) {
        return nativeStartMdnsDiscovery(nativeClientPtr, serviceName);
    }
    
    /**
     * Stops mDNS discovery.
     */
    public void stopMdnsDiscovery() {
        nativeStopMdnsDiscovery(nativeClientPtr);
    }
    
    /**
     * Checks if mDNS discovery is running.
     * 
     * @return true if mDNS is running, false otherwise
     */
    public boolean isMdnsRunning() {
        return nativeIsMdnsRunning(nativeClientPtr);
    }
    
    /**
     * Sends a file to a peer.
     * 
     * @param peerId The ID of the target peer
     * @param filePath The local path of the file to send
     * @param remoteFilename The filename as it should appear on the remote peer
     * @return The transfer ID on success, null on failure
     */
    public String sendFile(String peerId, String filePath, String remoteFilename) {
        return nativeSendFile(nativeClientPtr, peerId, filePath, remoteFilename);
    }
    
    /**
     * Accepts an incoming file transfer.
     * 
     * @param transferId The transfer ID of the incoming file
     * @param localPath The local path where the file should be saved
     * @return SUCCESS on success, error code on failure
     */
    public int acceptFileTransfer(String transferId, String localPath) {
        return nativeAcceptFileTransfer(nativeClientPtr, transferId, localPath);
    }
    
    /**
     * Rejects an incoming file transfer.
     * 
     * @param transferId The transfer ID of the incoming file
     * @param reason The reason for rejection
     * @return SUCCESS on success, error code on failure
     */
    public int rejectFileTransfer(String transferId, String reason) {
        return nativeRejectFileTransfer(nativeClientPtr, transferId, reason);
    }
    
    // Callback setters
    public void setConnectionCallback(ConnectionCallback callback) {
        nativeSetConnectionCallback(nativeClientPtr, callback);
    }
    
    public void setStringCallback(StringMessageCallback callback) {
        nativeSetStringCallback(nativeClientPtr, callback);
    }
    
    public void setBinaryCallback(BinaryMessageCallback callback) {
        nativeSetBinaryCallback(nativeClientPtr, callback);
    }
    
    public void setJsonCallback(JsonMessageCallback callback) {
        nativeSetJsonCallback(nativeClientPtr, callback);
    }
    
    public void setDisconnectCallback(DisconnectCallback callback) {
        nativeSetDisconnectCallback(nativeClientPtr, callback);
    }
    
    // Static utility methods
    public static String getVersionString() {
        return nativeGetVersionString();
    }
    
    public static int[] getVersion() {
        return nativeGetVersion();
    }
    
    public static String getGitDescribe() {
        return nativeGetGitDescribe();
    }
    
    public static int getAbi() {
        return nativeGetAbi();
    }
    
    public static void setLoggingEnabled(boolean enabled) {
        nativeSetLoggingEnabled(enabled);
    }
    
    public static void setLogLevel(String level) {
        nativeSetLogLevel(level);
    }
    
    // Native method declarations
    private static native String nativeGetVersionString();
    private static native int[] nativeGetVersion();
    private static native String nativeGetGitDescribe();
    private static native int nativeGetAbi();
    private static native void nativeSetLoggingEnabled(boolean enabled);
    private static native void nativeSetLogLevel(String level);
    
    private native long nativeCreate(int listenPort);
    private native void nativeDestroy(long clientPtr);
    private native int nativeStart(long clientPtr);
    private native void nativeStop(long clientPtr);
    
    private native int nativeConnect(long clientPtr, String host, int port);
    private native int nativeConnectWithStrategy(long clientPtr, String host, int port, int strategy);
    private native int nativeSendString(long clientPtr, String peerId, String message);
    private native int nativeBroadcastString(long clientPtr, String message);
    private native int nativeSendBinary(long clientPtr, String peerId, byte[] data);
    private native int nativeBroadcastBinary(long clientPtr, byte[] data);
    private native int nativeSendJson(long clientPtr, String peerId, String jsonStr);
    private native int nativeBroadcastJson(long clientPtr, String jsonStr);
    
    private native int nativeGetPeerCount(long clientPtr);
    private native String nativeGetOurPeerId(long clientPtr);
    private native String nativeGetConnectionStatisticsJson(long clientPtr);
    private native String[] nativeGetPeerIds(long clientPtr);
    
    private native int nativeSetEncryptionEnabled(long clientPtr, boolean enabled);
    private native boolean nativeIsEncryptionEnabled(long clientPtr);
    private native String nativeGenerateEncryptionKey(long clientPtr);
    private native int nativeSetEncryptionKey(long clientPtr, String key);
    
    private native int nativeStartDhtDiscovery(long clientPtr, int dhtPort);
    private native void nativeStopDhtDiscovery(long clientPtr);
    private native boolean nativeIsDhtRunning(long clientPtr);
    
    private native int nativeStartMdnsDiscovery(long clientPtr, String serviceName);
    private native void nativeStopMdnsDiscovery(long clientPtr);
    private native boolean nativeIsMdnsRunning(long clientPtr);
    
    private native String nativeSendFile(long clientPtr, String peerId, String filePath, String remoteFilename);
    private native int nativeAcceptFileTransfer(long clientPtr, String transferId, String localPath);
    private native int nativeRejectFileTransfer(long clientPtr, String transferId, String reason);
    
    private native void nativeSetConnectionCallback(long clientPtr, ConnectionCallback callback);
    private native void nativeSetStringCallback(long clientPtr, StringMessageCallback callback);
    private native void nativeSetBinaryCallback(long clientPtr, BinaryMessageCallback callback);
    private native void nativeSetJsonCallback(long clientPtr, JsonMessageCallback callback);
    private native void nativeSetDisconnectCallback(long clientPtr, DisconnectCallback callback);
}
