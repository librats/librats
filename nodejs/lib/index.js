/**
 * LibRats Node.js bindings.
 *
 * High-performance peer-to-peer networking: secure transport (Noise XX),
 * DHT/mDNS discovery, raw-channel messaging, pub/sub (GossipSub), typed JSON
 * messaging, file transfer, RTT probing and automatic reconnection.
 *
 * Subsystems are explicit and opt-in: call the matching `enable*()` BEFORE
 * `start()`. Callbacks must also be registered before `start()`. Native calls
 * throw an Error (message "librats: <CODE>") on a non-OK result.
 */

'use strict';

const path = require('path');
const fs = require('fs');

// Locate and load the compiled native addon.
let addon;
let addonPath;
const possiblePaths = [
  path.join(__dirname, '..', 'build', 'Release', 'librats.node'),
  path.join(__dirname, '..', 'build', 'Debug', 'librats.node'),
  path.join(__dirname, '..', 'build', 'librats.node'),
];
for (const tryPath of possiblePaths) {
  try {
    if (fs.existsSync(tryPath)) {
      addon = require(tryPath);
      addonPath = tryPath;
      break;
    }
  } catch (err) {
    // try next
  }
}
if (!addon) {
  throw new Error(
    'Could not load librats native addon. ' +
    'Make sure the package is installed correctly and the native library is built. ' +
    'Try running: npm rebuild librats'
  );
}

/** Transport security selector (see rats_security_t). */
const Security = Object.freeze({
  NOISE: 0,     // Noise XX, encrypted + authenticated (default)
  PLAINTEXT: 1, // unencrypted, ids exchanged in the clear
});

/** Global log levels (see rats_log_level_t). */
const LogLevel = Object.freeze({
  DEBUG: 0,
  INFO: 1,
  WARN: 2,
  ERROR: 3,
});

/**
 * A librats node.
 *
 * Construct with a listen port (`new RatsClient(8080)`) or a config object
 * (`new RatsClient({ listenPort, security, dataDir, ... })`). The instance is a
 * thin wrapper over the native handle; every method maps to a `rats_*` C call.
 */
class RatsClient {
  /**
   * @param {number|object} [portOrConfig] - listen port (0 = ephemeral) or a
   *   config object: { listenPort, enableListen, bindAddress, security,
   *   dataDir, protocolName, protocolVersion, maxPeers }.
   */
  constructor(portOrConfig = 0) {
    this._native = new addon.RatsClient(portOrConfig);
  }

  // ---- lifecycle / core ----

  /** Start the node. Throws on bind failure or if already started. */
  start() { this._native.start(); }

  /** Stop the node. Safe to call repeatedly. */
  stop() { this._native.stop(); }

  /** @returns {number} the actual listen port (resolved if 0 was requested). */
  getListenPort() { return this._native.getListenPort(); }

  /** @returns {string|null} our self-certifying peer id (64-char hex). */
  getOurPeerId() { return this._native.getOurPeerId(); }

  /** @returns {string|null} the application protocol name bound in the handshake. */
  getProtocolName() { return this._native.getProtocolName(); }

  /** @returns {string|null} the application protocol version. */
  getProtocolVersion() { return this._native.getProtocolVersion(); }

  // ---- connections ----

  /** Dial a peer. Throws on invalid argument. @param {string} host @param {number} port */
  connect(host, port) { this._native.connect(host, port); }

  /** @returns {number} count of currently-connected peers. */
  getPeerCount() { return this._native.getPeerCount(); }

  /** @returns {string[]} hex ids of currently-connected peers. */
  getPeerIds() { return this._native.getPeerIds(); }

  /** Cap on established peers (0 = unlimited). May be set before or after start. */
  setMaxPeers(maxPeers) { this._native.setMaxPeers(maxPeers); }

  /** @returns {number} the established-peer cap (0 = unlimited). */
  getMaxPeers() { return this._native.getMaxPeers(); }

  // ---- raw channel messaging ----

  /**
   * Send raw bytes on a named channel to one peer.
   * @param {string} peerId @param {string} channel @param {string|Buffer} data
   */
  send(peerId, channel, data) { this._native.send(peerId, channel, data); }

  /**
   * Broadcast raw bytes on a named channel to every connected peer.
   * @param {string} channel @param {string|Buffer} data
   */
  broadcast(channel, data) { this._native.broadcast(channel, data); }

  /**
   * Register a handler for a named channel. Register before start().
   * @param {string} channel
   * @param {(peerId: string, data: Buffer) => void} callback
   */
  on(channel, callback) { this._native.on(channel, callback); }

  // ---- peer events ----

  /** @param {(peerId: string) => void} callback fired when a peer connects. Register before start(). */
  onPeerConnected(callback) { this._native.onPeerConnected(callback); }

  /** @param {(peerId: string) => void} callback fired when a peer disconnects. Register before start(). */
  onPeerDisconnected(callback) { this._native.onPeerDisconnected(callback); }

  // ---- discovery / NAT (enable before start) ----

  /**
   * Enable DHT discovery.
   * @param {number} [dhtPort=0] 0 = ephemeral
   * @param {string} [discoveryKey] app namespace (default if omitted)
   */
  enableDht(dhtPort = 0, discoveryKey) { this._native.enableDht(dhtPort, discoveryKey); }

  /** Enable local-network mDNS discovery. */
  enableMdns() { this._native.enableMdns(); }

  /**
   * Enable automatic NAT port forwarding for the listen port.
   * @param {boolean} [enableUpnp=true] @param {boolean} [enableNatpmp=true]
   */
  enablePortMapping(enableUpnp = true, enableNatpmp = true) {
    this._native.enablePortMapping(enableUpnp, enableNatpmp);
  }

  // ---- pub/sub (enable before start) ----

  /** Enable the pub/sub (GossipSub) subsystem. */
  enablePubsub() { this._native.enablePubsub(); }

  /**
   * Subscribe to a topic. Subscribe before start().
   * @param {string} topic
   * @param {(peerId: string, topic: string, data: Buffer) => void} callback
   */
  subscribe(topic, callback) { this._native.subscribe(topic, callback); }

  /** Unsubscribe from a topic. @param {string} topic */
  unsubscribe(topic) { this._native.unsubscribe(topic); }

  /** Publish raw bytes on a topic. @param {string} topic @param {string|Buffer} data */
  publish(topic, data) { this._native.publish(topic, data); }

  // ---- typed JSON (enable before start) ----

  /** Enable the JSON-messaging subsystem. */
  enableJson() { this._native.enableJson(); }

  /**
   * Register an additive handler for JSON messages of `type`.
   * @param {string} type
   * @param {(peerId: string, json: string) => void} callback
   */
  onJson(type, callback) { this._native.onJson(type, callback); }

  /** Like onJson but the handler is removed after it fires once. */
  onceJson(type, callback) { this._native.onceJson(type, callback); }

  /** Remove handlers for a JSON message type. @param {string} type */
  offJson(type) { this._native.offJson(type); }

  /**
   * Send a typed JSON message to one peer.
   * @param {string} peerId @param {string} type @param {string} json valid JSON text
   */
  sendJson(peerId, type, json) { this._native.sendJson(peerId, type, json); }

  /** Broadcast a typed JSON message. @param {string} type @param {string} json valid JSON text */
  broadcastJson(type, json) { this._native.broadcastJson(type, json); }

  // ---- file transfer (enable + register callbacks before start) ----

  /** Enable the file-transfer subsystem. @param {string} [tempDir] in-progress download dir */
  enableFileTransfer(tempDir) { this._native.enableFileTransfer(tempDir); }

  /**
   * Fired for every incoming transfer offer. Respond with acceptFile()/rejectFile().
   * @param {(peerId: string, transferId: number, name: string, size: number, isDirectory: boolean) => void} callback
   */
  onFileOffer(callback) { this._native.onFileOffer(callback); }

  /**
   * Fired periodically with transfer progress. `status` is the numeric transfer state.
   * @param {(transferId: number, peerId: string, bytesTransferred: number, totalBytes: number, status: number) => void} callback
   */
  onFileProgress(callback) { this._native.onFileProgress(callback); }

  /**
   * Fired when a transfer finishes. `path` is the final on-disk path on success.
   * @param {(transferId: number, success: boolean, path: string) => void} callback
   */
  onFileComplete(callback) { this._native.onFileComplete(callback); }

  /** Offer a file to a peer. @returns {number} transfer id (0 on failure). */
  sendFile(peerId, filePath) { return this._native.sendFile(peerId, filePath); }

  /** Offer a directory tree to a peer. @returns {number} transfer id (0 on failure). */
  sendDirectory(peerId, dirPath) { return this._native.sendDirectory(peerId, dirPath); }

  /**
   * Accept an offered transfer.
   * @param {string} peerId @param {number} transferId
   * @param {string} destPath file path (single file) or destination directory
   */
  acceptFile(peerId, transferId, destPath) {
    this._native.acceptFile(peerId, transferId, destPath);
  }

  /** Reject an offered transfer. */
  rejectFile(peerId, transferId) { this._native.rejectFile(peerId, transferId); }

  /** Cancel a live transfer (either side). */
  cancelFile(peerId, transferId) { this._native.cancelFile(peerId, transferId); }

  /** Pause a live transfer. */
  pauseFile(peerId, transferId) { this._native.pauseFile(peerId, transferId); }

  /** Resume a paused transfer. */
  resumeFile(peerId, transferId) { this._native.resumeFile(peerId, transferId); }

  // ---- ping / reconnect (enable before start) ----

  /** Enable periodic ping/pong RTT probing of every peer. */
  enablePing() { this._native.enablePing(); }

  /** @returns {number} last RTT to a peer in ms, or -1 if unknown. */
  getPeerRttMs(peerId) { return this._native.getPeerRttMs(peerId); }

  /** Enable the reconnection subsystem (re-dials dropped peers with backoff). */
  enableReconnect() { this._native.enableReconnect(); }

  /** Add an address to keep connected. @param {string} host @param {number} port */
  addReconnect(host, port) { this._native.addReconnect(host, port); }

  /** Stop reconnecting to an address and drop it from the store. */
  removeReconnect(host, port) { this._native.removeReconnect(host, port); }
}

module.exports = {
  RatsClient,
  Security,
  LogLevel,

  // Library info
  getVersionString: addon.getVersionString,
  getVersion: addon.getVersion,
  getGitDescribe: addon.getGitDescribe,
  getAbi: addon.getAbi,

  // Global logging
  setLogLevel: addon.setLogLevel,
  setLogFile: addon.setLogFile,

  // Native constant tables (SECURITY, LOG_LEVELS, ERRORS)
  constants: addon.constants,
};

if (process.env.LIBRATS_DEBUG) {
  console.log(`[librats] Loaded native addon from: ${addonPath}`);
  console.log(`[librats] Version: ${addon.getVersionString()}`);
}
