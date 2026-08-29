/**
 * librats — Node.js bindings.
 *
 * A `RatsNode` is one librats node: secure transport (Noise XX over TCP or the
 * library's reliable stream over UDP), a self-certifying peer id, and raw
 * messaging on named channels. Everything else — DHT/mDNS discovery, pub/sub,
 * typed JSON messaging, file transfer, NAT port mapping, hole punching, RTT
 * probing, automatic reconnection — is an opt-in subsystem.
 *
 * Ordering: enable subsystems and register callbacks BEFORE `start()`. Enabling
 * after start throws `ALREADY_STARTED`; using a subsystem before its enable
 * throws `NOT_ENABLED`. Callbacks fire on a librats reactor thread and are
 * marshalled onto the JS thread — keep them non-blocking anyway.
 *
 * Failures throw an `Error` whose message is `librats: <CODE>`.
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

/** Transport security selector (`rats_security_t`). */
const Security = Object.freeze({
  NOISE: 0,     // Noise XX, encrypted + authenticated (default)
  PLAINTEXT: 1, // unencrypted, ids exchanged in the clear
});

/**
 * Which wire a peer connection runs on (`rats_transport_t`). Both carry the
 * identical protocol and the identical encrypted handshake; they differ only in
 * how the ordered, reliable byte stream underneath is obtained.
 */
const Transport = Object.freeze({
  TCP: 0,   // one kernel socket per peer
  UDP: 1,   // reliable stream over the shared UDP socket
  RELAY: 2, // carried through a third node (see enableRelay)
});

/** Bitmask flags used by `node.transports` and `node.peerTransports()`. */
const TransportMask = Object.freeze({
  TCP: 0x1,
  UDP: 0x2,
});

/**
 * What the mesh has shown about this node's own NAT, from the endpoints
 * datagram peers report seeing its shared UDP socket at.
 */
const NatMapping = Object.freeze({
  UNKNOWN: 0,               // not enough independent observations yet
  OPEN: 1,                  // no NAT in the path
  ENDPOINT_INDEPENDENT: 2,  // one external port for every peer — punchable
  ENDPOINT_DEPENDENT: 3,    // a fresh mapping per peer (symmetric) — not punchable
});

/** Process-global log levels (`rats_log_level_t`). */
const LogLevel = Object.freeze({
  DEBUG: 0,
  INFO: 1,
  WARN: 2,
  ERROR: 3,
});

/**
 * A librats node.
 *
 * ```js
 * const { RatsNode } = require('librats');
 * const node = new RatsNode({ listenPort: 8080, dataDir: './state' });
 * node.onPeerConnected(id => console.log('peer', id));
 * node.on('chat', (id, data) => console.log(id, data.toString()));
 * node.enableDht();
 * node.start();
 * ```
 */
class RatsNode {
  /**
   * @param {number|RatsNodeConfig} [portOrConfig=0] listen port (0 = ephemeral)
   *   or a config object. Both transports are enabled by default and bind the
   *   same port; a dial tries `preferredTransport` (UDP — one socket and one NAT
   *   mapping for every peer) and races the other after `transportFallbackMs`.
   */
  constructor(portOrConfig = 0) {
    this._native = new addon.RatsNode(portOrConfig);
  }

  // ---- lifecycle ----

  /** Bring the node up: bind the listener and start enabled subsystems. */
  start() { this._native.start(); }

  /** Tear the node down and close all connections. Idempotent. */
  stop() { this._native.stop(); }

  /**
   * Release the native node. The instance is inert afterwards — further calls
   * throw. Optional: an unreachable node is freed by the GC anyway.
   */
  destroy() { this._native.destroy(); }

  // ---- identity / info ----

  /** @type {number} the bound listen port (resolved when 0 was requested). */
  get listenPort() { return this._native.listenPort(); }

  /** @type {string|null} our self-certifying peer id (64-char lowercase hex). */
  get localId() { return this._native.localId(); }

  /** @type {string|null} the app protocol bound into the handshake, e.g. "librats/1.0". */
  get protocol() { return this._native.protocol(); }

  /**
   * @type {number} transports actually running, as a {@link TransportMask}
   * bitmask. May be narrower than the config asked for — a UDP socket that could
   * not be bound leaves the node TCP-only rather than failing to start. 0 before
   * `start()` and after `stop()`.
   */
  get transports() { return this._native.transports(); }

  // ---- connections ----

  /**
   * Dial a peer. Non-blocking: success surfaces as `onPeerConnected`.
   * @param {string} host @param {number} port
   */
  connect(host, port) { this._native.connect(host, port); }

  /** @type {number} count of currently-connected peers. */
  get peerCount() { return this._native.peerCount(); }

  /** @type {string[]} hex ids of currently-connected peers. */
  get peerIds() { return this._native.peerIds(); }

  /** @type {number} cap on established peers (0 = unlimited). Settable at any time. */
  get maxPeers() { return this._native.maxPeers(); }
  set maxPeers(n) { this._native.setMaxPeers(n); }

  /**
   * Which wire a connected peer's link runs on.
   * @param {string} peerId
   * @returns {number|null} a {@link Transport} value, or null if not connected.
   */
  peerTransport(peerId) { return this._native.peerTransport(peerId); }

  /**
   * Transports a connected peer advertised in its identify message.
   * @param {string} peerId
   * @returns {number|null} a {@link TransportMask} bitmask, or null if not
   *   connected. 0 means the peer did not say (an older build) — "no
   *   information", not "no transports".
   */
  peerTransports(peerId) { return this._native.peerTransports(peerId); }

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
   * Whether this peer's send queue still has room. False means pause and wait for
   * `onPeerWritable` — keep sending regardless and the peer is dropped with
   * reason `RATS_CLOSE_SLOW_CONSUMER`.
   * @param {string} peerId @returns {boolean}
   */
  peerWritable(peerId) { return this._native.peerWritable(peerId); }

  /**
   * Register a handler for a named channel. Additive; register before `start()`.
   * @param {string} channel
   * @param {(peerId: string, data: Buffer) => void} handler
   */
  on(channel, handler) { this._native.on(channel, handler); }

  // ---- peer events (register before start) ----

  /** @param {(peerId: string) => void} handler fired when a peer connects. */
  onPeerConnected(handler) { this._native.onPeerConnected(handler); }

  /**
   * @param {(peerId: string, reason: string) => void} handler fired when a peer
   * disconnects. `reason` is a name like "RATS_CLOSE_SLOW_CONSUMER", which means
   * this node was sending faster than the link drained.
   */
  onPeerDisconnected(handler) { this._native.onPeerDisconnected(handler); }

  /** @param {(peerId: string) => void} handler fired when a full queue drained. */
  onPeerWritable(handler) { this._native.onPeerWritable(handler); }

  // ---- discovery (enable before start) ----

  /**
   * Enable DHT discovery: announce on and search a key on the mainline DHT,
   * dialing what it finds.
   * @param {number} [dhtPort=0] 0 = ephemeral
   * @param {string} [discoveryKey] app namespace; defaults to the node's protocol
   */
  enableDht(dhtPort = 0, discoveryKey) { this._native.enableDht(dhtPort, discoveryKey); }

  /** Enable local-network mDNS discovery. */
  enableMdns() { this._native.enableMdns(); }

  // ---- NAT traversal (enable before start) ----

  /**
   * Enable automatic NAT port forwarding for the listen port.
   * @param {boolean} [enableUpnp=true] UPnP IGD backend
   * @param {boolean} [enableNatpmp=true] NAT-PMP backend
   */
  enablePortMapping(enableUpnp = true, enableNatpmp = true) {
    this._native.enablePortMapping(enableUpnp, enableNatpmp);
  }

  /**
   * Enable UDP hole punching: reach a peer no port forwarding made reachable by
   * arranging with a peer both sides already have that the two dial each other
   * at the same moment.
   * @param {boolean} [serveAsRelay=true] also carry other peers' rendezvous — a
   *   few dozen forwarded bytes per punch, only ever to peers this node already
   *   holds. A mesh in which nobody relays cannot punch at all.
   */
  enableHolePunch(serveAsRelay = true) { this._native.enableHolePunch(serveAsRelay); }

  /**
   * Try to reach a peer by punching. Non-blocking: success arrives as an
   * ordinary `onPeerConnected`. Throws `NO_SUCH_PEER` when there is nothing to
   * do or nothing to try with — already connected, a punch already running, or
   * this node does not yet know an external endpoint of its own.
   * @param {string} peerId
   */
  punchPeer(peerId) { this._native.punchPeer(peerId); }

  /**
   * Enable relaying: reach a peer that neither port forwarding nor hole punching
   * could make reachable, by routing the connection through a node both ends are
   * already connected to. The peer that comes out is ordinary in every way — the
   * same end-to-end encryption, the same channels — except that `peerTransport()`
   * reports it as `Transport.RELAY`.
   * @param {boolean} [serveAsRelay=false] also carry OTHER peers' connections.
   *   Unlike a hole-punch rendezvous this spends real bandwidth on somebody else's
   *   traffic, so it is off by default; a mesh in which nobody serves cannot relay.
   */
  enableRelay(serveAsRelay = false) { this._native.enableRelay(serveAsRelay); }

  /**
   * Try to reach a peer through a relay. Non-blocking: success arrives as an
   * ordinary `onPeerConnected`. Throws `NO_SUCH_PEER` when there is nothing to do
   * or nothing to try with — already connected, an attempt already running, in
   * cooldown, or no peer that could carry the connection. Usually unnecessary:
   * with hole punching enabled too, a punch that cannot work hands the target over
   * by itself.
   * @param {string} peerId
   */
  connectViaRelay(peerId) { this._native.connectViaRelay(peerId); }

  /** @type {number} a {@link NatMapping} value describing this node's own NAT. */
  get natMapping() { return this._native.natMapping(); }

  // ---- pub/sub (enable before start) ----

  /** Enable the pub/sub (GossipSub) subsystem. */
  enablePubsub() { this._native.enablePubsub(); }

  /**
   * Subscribe to a topic. Subscribe before `start()`.
   * @param {string} topic
   * @param {(peerId: string, topic: string, data: Buffer) => void} handler
   */
  subscribe(topic, handler) { this._native.subscribe(topic, handler); }

  /** Unsubscribe from a topic. @param {string} topic */
  unsubscribe(topic) { this._native.unsubscribe(topic); }

  /** Publish raw bytes on a topic. @param {string} topic @param {string|Buffer} data */
  publish(topic, data) { this._native.publish(topic, data); }

  // ---- typed JSON messaging (enable before start) ----

  /** Enable the typed-JSON messaging subsystem. */
  enableJson() { this._native.enableJson(); }

  /**
   * Register an additive handler for JSON messages of `type`.
   * @param {string} type
   * @param {(peerId: string, value: any) => void} handler receives the parsed value
   */
  onJson(type, handler) { this._native.onJson(type, wrapJson(handler)); }

  /** Like {@link onJson}, but the handler is removed after it fires once. */
  onceJson(type, handler) { this._native.onceJson(type, wrapJson(handler)); }

  /** Remove the handlers for a JSON message type. @param {string} type */
  offJson(type) { this._native.offJson(type); }

  /**
   * Send a typed JSON message to one peer.
   * @param {string} peerId @param {string} type
   * @param {any} value serialized with `JSON.stringify` unless already a string
   */
  sendJson(peerId, type, value) { this._native.sendJson(peerId, type, toJsonText(value)); }

  /** Broadcast a typed JSON message. @param {string} type @param {any} value */
  broadcastJson(type, value) { this._native.broadcastJson(type, toJsonText(value)); }

  // ---- file transfer (enable + register callbacks before start) ----

  /**
   * Enable the file-transfer subsystem.
   * @param {string} [tempDir] directory for in-progress downloads (default ".")
   */
  enableFileTransfer(tempDir) { this._native.enableFileTransfer(tempDir); }

  /**
   * Fired for every incoming offer. Respond with {@link acceptFile} / {@link rejectFile}.
   * @param {(peerId: string, transferId: number, name: string, size: number, isDirectory: boolean) => void} handler
   */
  onFileOffer(handler) { this._native.onFileOffer(handler); }

  /**
   * Fired periodically with transfer progress. `status` is the numeric transfer state.
   * @param {(transferId: number, peerId: string, bytesTransferred: number, totalBytes: number, status: number) => void} handler
   */
  onFileProgress(handler) { this._native.onFileProgress(handler); }

  /**
   * Fired when a transfer finishes; `path` is the final on-disk path on success.
   * @param {(transferId: number, success: boolean, path: string) => void} handler
   */
  onFileComplete(handler) { this._native.onFileComplete(handler); }

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

  /** Pause a live transfer (either side). */
  pauseFile(peerId, transferId) { this._native.pauseFile(peerId, transferId); }

  /** Resume a paused transfer (either side). */
  resumeFile(peerId, transferId) { this._native.resumeFile(peerId, transferId); }

  // ---- liveness / reconnection (enable before start) ----

  /** Enable periodic ping/pong RTT probing of every peer. */
  enablePing() { this._native.enablePing(); }

  /**
   * @param {string} peerId
   * @returns {number} last measured RTT in ms, or -1 if unknown (ping not
   *   enabled, or no pong received yet).
   */
  peerRttMs(peerId) { return this._native.peerRttMs(peerId); }

  /** Enable the reconnection subsystem: re-dials dropped peers with backoff. */
  enableReconnect() { this._native.enableReconnect(); }

  /** Add an address to keep connected (re-dialed on drop). @param {string} host @param {number} port */
  addReconnect(host, port) { this._native.addReconnect(host, port); }

  /** Stop reconnecting to an address and drop it from the store. */
  removeReconnect(host, port) { this._native.removeReconnect(host, port); }
}

// JSON messaging is "a named type carrying a JSON document". The C ABI speaks
// JSON text; JS speaks values, so the conversion lives here rather than in every
// caller. A string is passed through — it is either already JSON text or a JSON
// string the peer will parse back to a string either way.
function toJsonText(value) {
  return typeof value === 'string' ? value : JSON.stringify(value);
}

function wrapJson(handler) {
  return (peerId, json) => {
    let value;
    try {
      value = JSON.parse(json);
    } catch (err) {
      value = json; // hand over the raw text rather than dropping the message
    }
    handler(peerId, value);
  };
}

module.exports = {
  RatsNode,

  // Enums
  Security,
  Transport,
  TransportMask,
  NatMapping,
  LogLevel,

  // Library info
  version: addon.getVersionString,
  versionInfo: addon.getVersion,
  gitDescribe: addon.getGitDescribe,
  abi: addon.getAbi,

  // Process-global logging
  setLogLevel: addon.setLogLevel,
  setLogFile: addon.setLogFile,
};

if (process.env.LIBRATS_DEBUG) {
  console.log(`[librats] Loaded native addon from: ${addonPath}`);
  console.log(`[librats] Version: ${addon.getVersionString()}`);
}
