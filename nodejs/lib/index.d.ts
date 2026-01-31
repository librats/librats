/**
 * LibRats Node.js Bindings - TypeScript Definitions
 * 
 * High-performance peer-to-peer networking library with support for DHT, GossipSub,
 * file transfer, and more.
 */

/**
 * Version information structure
 */
export interface VersionInfo {
  major: number;
  minor: number;
  patch: number;
  build: number;
}

/**
 * Error codes returned by various operations
 */
export enum ErrorCodes {
  /** Operation completed successfully */
  SUCCESS = 0,
  /** Invalid client handle */
  INVALID_HANDLE = -1,
  /** Invalid parameter provided */
  INVALID_PARAMETER = -2,
  /** Client is not running */
  NOT_RUNNING = -3,
  /** Operation failed */
  OPERATION_FAILED = -4,
  /** Peer not found */
  PEER_NOT_FOUND = -5,
  /** Memory allocation error */
  MEMORY_ALLOCATION = -6,
  /** JSON parsing error */
  JSON_PARSE = -7
}

/**
 * ICE connection states
 */
export enum IceConnectionState {
  NEW = 0,
  GATHERING = 1,
  CHECKING = 2,
  CONNECTED = 3,
  COMPLETED = 4,
  FAILED = 5,
  DISCONNECTED = 6,
  CLOSED = 7
}

/**
 * ICE gathering states
 */
export enum IceGatheringState {
  NEW = 0,
  GATHERING = 1,
  COMPLETE = 2
}

/**
 * ICE candidate types
 */
export enum IceCandidateType {
  HOST = 0,
  SRFLX = 1,
  PRFLX = 2,
  RELAY = 3
}

/**
 * Main RatsClient class for peer-to-peer networking
 */
export class RatsClient {
  /**
   * Create a new RatsClient instance
   * @param listenPort - Port to listen on for incoming connections
   */
  constructor(listenPort: number);

  // ============ Basic Operations ============

  /**
   * Start the client
   * @returns true if started successfully, false otherwise
   */
  start(): boolean;

  /**
   * Stop the client
   */
  stop(): void;

  /**
   * Connect to a peer
   * @param host - IP address or hostname of the peer
   * @param port - Port number of the peer
   * @returns true if connection initiated successfully
   */
  connect(host: string, port: number): boolean;

  /**
   * Disconnect from a peer
   * @param peerId - ID of the peer to disconnect from
   */
  disconnect(peerId: string): void;

  // ============ Information ============

  /**
   * Get the port the client is listening on
   * @returns Listen port number
   */
  getListenPort(): number;

  /**
   * Get the number of connected peers
   * @returns Number of connected peers
   */
  getPeerCount(): number;

  /**
   * Get our own peer ID
   * @returns Our peer ID, or null if not started
   */
  getOurPeerId(): string | null;

  /**
   * Get list of connected peer IDs
   * @returns Array of peer IDs
   */
  getPeerIds(): string[];

  /**
   * Get connection statistics as JSON string
   * @returns JSON string with statistics, or null if unavailable
   */
  getConnectionStatistics(): string | null;

  /**
   * Get file transfer statistics as JSON string
   * @returns JSON string with statistics, or null if unavailable
   */
  getFileTransferStatistics(): string | null;

  // ============ Peer Management ============

  /**
   * Set maximum number of peers
   * @param maxPeers - Maximum number of peers to allow
   * @returns true if set successfully
   */
  setMaxPeers(maxPeers: number): boolean;

  /**
   * Get maximum number of peers
   * @returns Maximum number of peers allowed
   */
  getMaxPeers(): number;

  /**
   * Check if peer limit has been reached
   * @returns true if at or over peer limit
   */
  isPeerLimitReached(): boolean;

  // ============ Messaging ============

  /**
   * Send a string message to a peer
   * @param peerId - ID of the peer to send to
   * @param message - String message to send
   * @returns true if sent successfully
   */
  sendString(peerId: string, message: string): boolean;

  /**
   * Send binary data to a peer
   * @param peerId - ID of the peer to send to
   * @param data - Buffer containing binary data
   * @returns true if sent successfully
   */
  sendBinary(peerId: string, data: Buffer): boolean;

  /**
   * Send JSON data to a peer
   * @param peerId - ID of the peer to send to
   * @param jsonStr - JSON string to send
   * @returns true if sent successfully
   */
  sendJson(peerId: string, jsonStr: string): boolean;

  /**
   * Broadcast a string message to all connected peers
   * @param message - String message to broadcast
   * @returns Number of peers the message was sent to
   */
  broadcastString(message: string): number;

  /**
   * Broadcast binary data to all connected peers
   * @param data - Buffer containing binary data
   * @returns Number of peers the data was sent to
   */
  broadcastBinary(data: Buffer): number;

  /**
   * Broadcast JSON data to all connected peers
   * @param jsonStr - JSON string to broadcast
   * @returns Number of peers the data was sent to
   */
  broadcastJson(jsonStr: string): number;

  // ============ File Transfer ============

  /**
   * Send a file to a peer
   * @param peerId - ID of the peer to send to
   * @param filePath - Local path to the file
   * @param remoteFilename - Optional filename on remote side
   * @returns Transfer ID, or null if failed
   */
  sendFile(peerId: string, filePath: string, remoteFilename?: string): string | null;

  /**
   * Send a directory to a peer
   * @param peerId - ID of the peer to send to
   * @param dirPath - Local path to the directory
   * @param remoteDirName - Optional directory name on remote side
   * @param recursive - Whether to send recursively (default: true)
   * @returns Transfer ID, or null if failed
   */
  sendDirectory(peerId: string, dirPath: string, remoteDirName?: string, recursive?: boolean): string | null;

  /**
   * Request a file from a peer
   * @param peerId - ID of the peer to request from
   * @param remoteFilePath - Path to the file on remote side
   * @param localPath - Local path where file should be saved
   * @returns Transfer ID, or null if failed
   */
  requestFile(peerId: string, remoteFilePath: string, localPath: string): string | null;

  /**
   * Request a directory from a peer
   * @param peerId - ID of the peer to request from
   * @param remoteDirPath - Path to the directory on remote side
   * @param localDirPath - Local path where directory should be saved
   * @param recursive - Whether to request recursively (default: true)
   * @returns Transfer ID, or null if failed
   */
  requestDirectory(peerId: string, remoteDirPath: string, localDirPath: string, recursive?: boolean): string | null;

  /**
   * Accept an incoming file transfer
   * @param transferId - ID of the transfer to accept
   * @param localPath - Local path where file should be saved
   * @returns true if accepted successfully
   */
  acceptFileTransfer(transferId: string, localPath: string): boolean;

  /**
   * Reject an incoming file transfer
   * @param transferId - ID of the transfer to reject
   * @param reason - Optional reason for rejection
   * @returns true if rejected successfully
   */
  rejectFileTransfer(transferId: string, reason?: string): boolean;

  /**
   * Cancel an ongoing file transfer
   * @param transferId - ID of the transfer to cancel
   * @returns true if cancelled successfully
   */
  cancelFileTransfer(transferId: string): boolean;

  /**
   * Pause a file transfer
   * @param transferId - ID of the transfer to pause
   * @returns true if paused successfully
   */
  pauseFileTransfer(transferId: string): boolean;

  /**
   * Resume a paused file transfer
   * @param transferId - ID of the transfer to resume
   * @returns true if resumed successfully
   */
  resumeFileTransfer(transferId: string): boolean;

  /**
   * Get file transfer progress information as JSON string
   * @param transferId - ID of the transfer to query
   * @returns JSON string with progress info, or null if not found
   */
  getFileTransferProgress(transferId: string): string | null;

  // ============ GossipSub ============

  /**
   * Check if GossipSub is available
   * @returns true if GossipSub is available
   */
  isGossipsubAvailable(): boolean;

  /**
   * Check if GossipSub is running
   * @returns true if GossipSub is running
   */
  isGossipsubRunning(): boolean;

  /**
   * Subscribe to a topic
   * @param topic - Topic name to subscribe to
   * @returns true if subscribed successfully
   */
  subscribeToTopic(topic: string): boolean;

  /**
   * Unsubscribe from a topic
   * @param topic - Topic name to unsubscribe from
   * @returns true if unsubscribed successfully
   */
  unsubscribeFromTopic(topic: string): boolean;

  /**
   * Check if subscribed to a topic
   * @param topic - Topic name to check
   * @returns true if subscribed
   */
  isSubscribedToTopic(topic: string): boolean;

  /**
   * Publish a message to a topic
   * @param topic - Topic name to publish to
   * @param message - Message to publish
   * @returns true if published successfully
   */
  publishToTopic(topic: string, message: string): boolean;

  /**
   * Publish JSON data to a topic
   * @param topic - Topic name to publish to
   * @param jsonStr - JSON string to publish
   * @returns true if published successfully
   */
  publishJsonToTopic(topic: string, jsonStr: string): boolean;

  /**
   * Get list of subscribed topics
   * @returns Array of topic names
   */
  getSubscribedTopics(): string[];

  /**
   * Get peers subscribed to a topic
   * @param topic - Topic name
   * @returns Array of peer IDs
   */
  getTopicPeers(topic: string): string[];

  /**
   * Get GossipSub statistics as JSON string
   * @returns JSON string with statistics, or null if unavailable
   */
  getGossipsubStatistics(): string | null;

  // ============ DHT ============

  /**
   * Start DHT discovery
   * @param dhtPort - Port to use for DHT
   * @returns true if started successfully
   */
  startDhtDiscovery(dhtPort: number): boolean;

  /**
   * Stop DHT discovery
   */
  stopDhtDiscovery(): void;

  /**
   * Check if DHT is running
   * @returns true if DHT is running
   */
  isDhtRunning(): boolean;

  /**
   * Get DHT routing table size
   * @returns Number of entries in the routing table
   */
  getDhtRoutingTableSize(): number;

  /**
   * Announce availability for a content hash
   * @param contentHash - Hash to announce for
   * @param port - Port to announce
   * @param callback - Optional callback to receive discovered peers during DHT traversal
   * @returns true if announced successfully
   */
  announceForHash(contentHash: string, port: number, callback?: (peers: string[]) => void): boolean;

  // ============ mDNS ============

  /**
   * Start mDNS discovery
   * @param serviceName - Service name to advertise
   * @returns true if started successfully
   */
  startMdnsDiscovery(serviceName: string): boolean;

  /**
   * Stop mDNS discovery
   */
  stopMdnsDiscovery(): void;

  /**
   * Check if mDNS is running
   * @returns true if mDNS is running
   */
  isMdnsRunning(): boolean;

  /**
   * Query for mDNS services
   * @returns true if query sent successfully
   */
  queryMdnsServices(): boolean;

  // ============ Address Blocking ============

  /**
   * Add an IP address to the ignore list
   * @param ipAddress - IP address to ignore
   */
  addIgnoredAddress(ipAddress: string): void;

  // ============ Encryption ============

  /**
   * Enable or disable encryption
   * @param enabled - Whether encryption should be enabled
   * @returns true if set successfully
   */
  setEncryptionEnabled(enabled: boolean): boolean;

  /**
   * Check if encryption is enabled
   * @returns true if encryption is enabled
   */
  isEncryptionEnabled(): boolean;

  /**
   * Initialize encryption system
   * @param enable - Whether to enable encryption
   * @returns true if initialized successfully
   */
  initializeEncryption(enable: boolean): boolean;

  /**
   * Check if a specific peer connection is encrypted
   * @param peerId - Peer ID to check
   * @returns true if peer connection is encrypted
   */
  isPeerEncrypted(peerId: string): boolean;

  /**
   * Set custom Noise Protocol static keypair
   * @param privateKeyHex - 32-byte private key as 64-char hex string
   * @returns true if set successfully
   */
  setNoiseStaticKeypair(privateKeyHex: string): boolean;

  /**
   * Get our Noise Protocol static public key
   * @returns 64-char hex string, or null if not available
   */
  getNoiseStaticPublicKey(): string | null;

  /**
   * Get remote peer's Noise static public key
   * @param peerId - Peer ID to query
   * @returns 64-char hex string, or null if not available
   */
  getPeerNoisePublicKey(peerId: string): string | null;

  /**
   * Get handshake hash for channel binding
   * @param peerId - Peer ID to query
   * @returns 64-char hex string, or null if not available
   */
  getPeerHandshakeHash(peerId: string): string | null;

  // ============ ICE (NAT Traversal) ============

  /**
   * Check if ICE is available
   * @returns true if ICE is available
   */
  isIceAvailable(): boolean;

  /**
   * Add a STUN server for NAT traversal
   * @param host - STUN server hostname or IP
   * @param port - STUN server port (default: 3478)
   */
  addStunServer(host: string, port?: number): void;

  /**
   * Add a TURN server for relay-based NAT traversal
   * @param host - TURN server hostname or IP
   * @param port - TURN server port
   * @param username - TURN username
   * @param password - TURN password
   */
  addTurnServer(host: string, port: number, username: string, password: string): void;

  /**
   * Clear all ICE (STUN/TURN) servers
   */
  clearIceServers(): void;

  /**
   * Start gathering ICE candidates
   * @returns true if gathering started successfully
   */
  gatherIceCandidates(): boolean;

  /**
   * Get local ICE candidates as JSON string
   * @returns JSON string of candidates, or null if unavailable
   */
  getIceCandidates(): string | null;

  /**
   * Check if ICE candidate gathering is complete
   * @returns true if gathering is complete
   */
  isIceGatheringComplete(): boolean;

  /**
   * Get public address discovered via STUN
   * @returns Address string (ip:port), or null if not discovered
   */
  getPublicAddress(): string | null;

  /**
   * Perform a simple STUN binding request to discover public address
   * @param stunServer - STUN server hostname (default: "stun.l.google.com")
   * @param port - STUN server port (default: 19302)
   * @param timeoutMs - Timeout in milliseconds (default: 5000)
   * @returns Address string (ip:port), or null on failure
   */
  discoverPublicAddress(stunServer?: string, port?: number, timeoutMs?: number): string | null;

  /**
   * Add a remote ICE candidate from SDP
   * @param candidateSdp - SDP candidate string
   */
  addRemoteIceCandidate(candidateSdp: string): void;

  /**
   * Signal end of remote ICE candidates (trickle ICE complete)
   */
  endOfRemoteIceCandidates(): void;

  /**
   * Start ICE connectivity checks
   */
  startIceChecks(): void;

  /**
   * Get current ICE connection state
   * @returns ICE connection state value
   */
  getIceConnectionState(): number;

  /**
   * Get ICE gathering state
   * @returns ICE gathering state value
   */
  getIceGatheringState(): number;

  /**
   * Check if ICE is connected
   * @returns true if ICE connection is established
   */
  isIceConnected(): boolean;

  /**
   * Get the selected ICE candidate pair as JSON string
   * @returns JSON string of selected pair, or null if unavailable
   */
  getIceSelectedPair(): string | null;

  /**
   * Close ICE manager and release resources
   */
  closeIce(): void;

  /**
   * Restart ICE (re-gather candidates and restart checks)
   */
  restartIce(): void;

  // ============ Configuration Persistence ============

  /**
   * Set data directory for configuration files
   * @param directory - Path to data directory
   * @returns true if set successfully
   */
  setDataDirectory(directory: string): boolean;

  /**
   * Get current data directory
   * @returns Path to data directory, or null if not set
   */
  getDataDirectory(): string | null;

  /**
   * Save current configuration to disk
   * @returns true if saved successfully
   */
  saveConfiguration(): boolean;

  /**
   * Load configuration from disk
   * @returns true if loaded successfully
   */
  loadConfiguration(): boolean;

  // ============ Event Handlers ============

  /**
   * Set callback for when a peer connects
   * @param callback - Function to call with peer ID
   */
  onConnection(callback: (peerId: string) => void): void;

  /**
   * Set callback for string messages
   * @param callback - Function to call with peer ID and message
   */
  onString(callback: (peerId: string, message: string) => void): void;

  /**
   * Set callback for binary messages
   * @param callback - Function to call with peer ID and data
   */
  onBinary(callback: (peerId: string, data: Buffer) => void): void;

  /**
   * Set callback for JSON messages
   * @param callback - Function to call with peer ID and JSON string
   */
  onJson(callback: (peerId: string, jsonStr: string) => void): void;

  /**
   * Set callback for when a peer disconnects
   * @param callback - Function to call with peer ID
   */
  onDisconnect(callback: (peerId: string) => void): void;

  /**
   * Set callback for file transfer progress updates
   * @param callback - Function to call with transfer ID, progress percentage, and status
   */
  onFileProgress(callback: (transferId: string, progressPercent: number, status: string) => void): void;
}

// ============ Utility Functions ============

/**
 * Get the library version as a string
 * @returns Version string (e.g., "1.0.0.123")
 */
export function getVersionString(): string;

/**
 * Get the library version components
 * @returns Version information object
 */
export function getVersion(): VersionInfo;

/**
 * Get git describe string
 * @returns Git describe string
 */
export function getGitDescribe(): string;

/**
 * Get ABI version number
 * @returns ABI version
 */
export function getAbi(): number;

// ============ Logging Control Functions ============

/**
 * Enable or disable console logging.
 * When disabled, log messages will not be printed to stdout/stderr.
 * File logging (if enabled) will still work.
 * @param enabled - Whether to enable console logging (default: true)
 */
export function setConsoleLoggingEnabled(enabled: boolean): void;

/**
 * Check if console logging is currently enabled.
 * @returns true if console logging is enabled
 */
export function isConsoleLoggingEnabled(): boolean;
