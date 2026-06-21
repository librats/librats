/**
 * LibRats Node.js bindings - TypeScript definitions.
 *
 * High-performance peer-to-peer networking: secure transport (Noise XX),
 * DHT/mDNS discovery, raw-channel messaging, pub/sub (GossipSub), typed JSON
 * messaging, file transfer, RTT probing and automatic reconnection.
 */

/** Library version components. */
export interface VersionInfo {
  major: number;
  minor: number;
  patch: number;
  build: number;
}

/** Transport security selector. */
export enum Security {
  /** Noise XX, encrypted + authenticated (default). */
  NOISE = 0,
  /** Unencrypted; peer ids exchanged in the clear. */
  PLAINTEXT = 1,
}

/** Global log levels. */
export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
}

/**
 * Node configuration. Pass to the RatsClient constructor in place of a port.
 * Omitted fields take the library default.
 */
export interface RatsConfig {
  /** Inbound port; 0 = ephemeral. */
  listenPort?: number;
  /** false = dial-only node (no listener). Default true. */
  enableListen?: boolean;
  /** Bind address; default "::" dual-stack wildcard. */
  bindAddress?: string;
  /** Transport security. Default Security.NOISE. */
  security?: Security;
  /** Persistent state dir; empty/omitted = ephemeral identity each run. */
  dataDir?: string;
  /** Handshake app namespace; default "librats". */
  protocolName?: string;
  /** Handshake app version; default "1.0". */
  protocolVersion?: string;
  /** Established-peer cap; 0 = unlimited. */
  maxPeers?: number;
}

/**
 * A librats node.
 *
 * Subsystems are opt-in: call the matching `enable*()` BEFORE `start()`.
 * Callbacks must also be registered before `start()`. Methods throw an Error
 * (message "librats: <CODE>") on a non-OK native result.
 */
export class RatsClient {
  /**
   * @param portOrConfig - listen port (0 = ephemeral) or a config object.
   */
  constructor(portOrConfig?: number | RatsConfig);

  // ---- lifecycle / core ----

  /** Start the node. Throws on bind failure or if already started. */
  start(): void;

  /** Stop the node. Safe to call repeatedly. */
  stop(): void;

  /** The actual listen port (resolved if 0 was requested). */
  getListenPort(): number;

  /** Our self-certifying peer id (64-char hex), or null if unavailable. */
  getOurPeerId(): string | null;

  /** The application protocol name bound in the handshake. */
  getProtocolName(): string | null;

  /** The application protocol version. */
  getProtocolVersion(): string | null;

  // ---- connections ----

  /** Dial a peer. Throws on invalid argument. */
  connect(host: string, port: number): void;

  /** Count of currently-connected peers. */
  getPeerCount(): number;

  /** Hex ids of currently-connected peers. */
  getPeerIds(): string[];

  /** Cap on established peers (0 = unlimited). May be set before or after start. */
  setMaxPeers(maxPeers: number): void;

  /** The established-peer cap (0 = unlimited). */
  getMaxPeers(): number;

  // ---- raw channel messaging ----

  /** Send raw bytes on a named channel to one peer. */
  send(peerId: string, channel: string, data: string | Buffer): void;

  /** Broadcast raw bytes on a named channel to every connected peer. */
  broadcast(channel: string, data: string | Buffer): void;

  /** Register a handler for a named channel. Register before start(). */
  on(channel: string, callback: (peerId: string, data: Buffer) => void): void;

  // ---- peer events ----

  /** Fired when a peer connects. Register before start(). */
  onPeerConnected(callback: (peerId: string) => void): void;

  /** Fired when a peer disconnects. Register before start(). */
  onPeerDisconnected(callback: (peerId: string) => void): void;

  // ---- discovery / NAT (enable before start) ----

  /** Enable DHT discovery. dhtPort 0 = ephemeral; discoveryKey namespaces the app. */
  enableDht(dhtPort?: number, discoveryKey?: string): void;

  /** Enable local-network mDNS discovery. */
  enableMdns(): void;

  /** Enable automatic NAT port forwarding for the listen port (UPnP + NAT-PMP). */
  enablePortMapping(enableUpnp?: boolean, enableNatpmp?: boolean): void;

  // ---- pub/sub (enable before start) ----

  /** Enable the pub/sub (GossipSub) subsystem. */
  enablePubsub(): void;

  /** Subscribe to a topic. Subscribe before start(). */
  subscribe(
    topic: string,
    callback: (peerId: string, topic: string, data: Buffer) => void
  ): void;

  /** Unsubscribe from a topic. */
  unsubscribe(topic: string): void;

  /** Publish raw bytes on a topic to every subscribed peer. */
  publish(topic: string, data: string | Buffer): void;

  // ---- typed JSON (enable before start) ----

  /** Enable the JSON-messaging subsystem. */
  enableJson(): void;

  /** Register an additive handler for JSON messages of `type`. */
  onJson(type: string, callback: (peerId: string, json: string) => void): void;

  /** Like onJson but the handler is removed after it fires once. */
  onceJson(type: string, callback: (peerId: string, json: string) => void): void;

  /** Remove handlers for a JSON message type. */
  offJson(type: string): void;

  /** Send a typed JSON message to one peer. `json` must be valid JSON text. */
  sendJson(peerId: string, type: string, json: string): void;

  /** Broadcast a typed JSON message. `json` must be valid JSON text. */
  broadcastJson(type: string, json: string): void;

  // ---- file transfer (enable + register callbacks before start) ----

  /** Enable the file-transfer subsystem. tempDir holds in-progress downloads. */
  enableFileTransfer(tempDir?: string): void;

  /** Fired for every incoming transfer offer. Respond with acceptFile()/rejectFile(). */
  onFileOffer(
    callback: (
      peerId: string,
      transferId: number,
      name: string,
      size: number,
      isDirectory: boolean
    ) => void
  ): void;

  /** Fired periodically with transfer progress. `status` is the numeric transfer state. */
  onFileProgress(
    callback: (
      transferId: number,
      peerId: string,
      bytesTransferred: number,
      totalBytes: number,
      status: number
    ) => void
  ): void;

  /** Fired when a transfer finishes. `path` is the final on-disk path on success. */
  onFileComplete(
    callback: (transferId: number, success: boolean, path: string) => void
  ): void;

  /** Offer a file to a peer. Returns the transfer id (0 on failure). */
  sendFile(peerId: string, filePath: string): number;

  /** Offer a directory tree to a peer. Returns the transfer id (0 on failure). */
  sendDirectory(peerId: string, dirPath: string): number;

  /** Accept an offered transfer. destPath is a file path or destination directory. */
  acceptFile(peerId: string, transferId: number, destPath: string): void;

  /** Reject an offered transfer. */
  rejectFile(peerId: string, transferId: number): void;

  /** Cancel a live transfer (either side). */
  cancelFile(peerId: string, transferId: number): void;

  /** Pause a live transfer. */
  pauseFile(peerId: string, transferId: number): void;

  /** Resume a paused transfer. */
  resumeFile(peerId: string, transferId: number): void;

  // ---- ping / reconnect (enable before start) ----

  /** Enable periodic ping/pong RTT probing of every peer. */
  enablePing(): void;

  /** Last RTT to a peer in ms, or -1 if unknown. */
  getPeerRttMs(peerId: string): number;

  /** Enable the reconnection subsystem (re-dials dropped peers with backoff). */
  enableReconnect(): void;

  /** Add an address to keep connected (re-dialed on drop). */
  addReconnect(host: string, port: number): void;

  /** Stop reconnecting to an address and drop it from the store. */
  removeReconnect(host: string, port: number): void;
}

// ---- library info (process-global) ----

/** Library version as a string, e.g. "1.2.3.45". */
export function getVersionString(): string;

/** Library version components. */
export function getVersion(): VersionInfo;

/** Git describe of the build, e.g. "v1.2.3-4-gabcdef". */
export function getGitDescribe(): string;

/** Packed ABI id as (major<<16)|(minor<<8)|patch. */
export function getAbi(): number;

// ---- global logging ----

/** Set the global log level. */
export function setLogLevel(level: LogLevel): void;

/** Mirror logs to a file (omit/empty to disable file logging). */
export function setLogFile(path?: string): void;

/** Native constant tables. */
export const constants: {
  SECURITY: { NOISE: number; PLAINTEXT: number };
  LOG_LEVELS: { DEBUG: number; INFO: number; WARN: number; ERROR: number };
  ERRORS: {
    OK: number;
    INVALID_ARG: number;
    NOT_STARTED: number;
    ALREADY_STARTED: number;
    NOT_ENABLED: number;
    NO_SUCH_PEER: number;
    BIND: number;
    INTERNAL: number;
  };
};
