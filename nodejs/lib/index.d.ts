/**
 * TypeScript definitions for librats — Node.js bindings over the librats C API.
 *
 * Enumerations are lowercase strings. Failures throw an `Error` whose `code`
 * is one of {@link ErrorCode}.
 */

/// <reference types="node" />

declare module 'librats' {
  /** The wire a connection runs on. `relay` is reported, never chosen. */
  export type Transport = 'udp' | 'tcp' | 'relay';
  /** A transport a node can run and dial. */
  export type DialTransport = 'udp' | 'tcp';
  export type Direction = 'inbound' | 'outbound';
  export type Security = 'noise' | 'plaintext';
  export type CongestionControl = 'bbr' | 'reno';
  export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

  /** What peers have shown about this node's NAT. */
  export type NatMapping =
    | 'unknown'               // not enough observations yet
    | 'open'                  // no NAT in the path
    | 'endpoint-independent'  // one external port for every peer: punchable
    | 'endpoint-dependent';   // a new mapping per peer (symmetric): not punchable

  /** Why a peer connection ended. */
  export type CloseReason =
    | 'local'             // we disconnected it
    | 'peer-closed'       // the peer closed cleanly
    | 'peer-reset'        // connection reset / socket error
    | 'connect-failed'    // the dial never completed
    | 'handshake-failed'  // secure handshake failed or timed out
    | 'protocol-error'    // malformed frame or decryption failure
    /**
     * We kept sending while the peer's queue was past its limit — the one reason
     * the application causes. Heed `peerWritable()` and `onPeerWritable`.
     */
    | 'slow-consumer'
    | 'shutdown'          // the node is stopping
    | 'duplicate'         // replaced by another connection to the same peer
    | 'peer-limit'        // inbound refused: maxPeers reached
    | 'idle-timeout'      // a UDP connection went silent
    | 'dial-superseded';  // a dial racing over the other transport won

  /** `code` of a thrown librats Error. */
  export type ErrorCode =
    | 'INVALID_ARG'
    | 'NOT_STARTED'
    | 'ALREADY_STARTED'
    | 'NOT_ENABLED'
    | 'NO_SUCH_PEER'
    | 'NOT_FOUND'
    | 'DECLINED'
    | 'BIND'
    | 'INTERNAL'
    /** The constructor's config cannot make a node (see RatsNodeConfig). */
    | 'INVALID_CONFIG'
    /** The node was destroyed. */
    | 'DESTROYED';

  /**
   * Node configuration. Every field is optional; the defaults are shown. The
   * constructor throws `INVALID_CONFIG` for a config no node can run with — no
   * transport, or a `preferredTransport` that `transports` leaves out.
   */
  export interface RatsNodeConfig {
    /** App id bound into the handshake; peers with a different one cannot connect. Default `'librats/1.0'`. */
    protocol?: string;
    /** Directory for persistent state (identity, DHT routing table, reconnect list). Default: none, a new identity each run. */
    dataDir?: string;
    /** Default `'noise'`. */
    security?: Security;

    /** Port shared by both transports. Default 0 (ephemeral). */
    listenPort?: number;
    /** Default `'::'`, dual-stack on every interface. */
    bindAddress?: string;
    /** No listener; outbound connections only. Default false. */
    dialOnly?: boolean;
    /** Cap on established peers, enforced on inbound. Default 0 (unlimited). */
    maxPeers?: number;

    /** Transports to run. Default `['udp', 'tcp']`. */
    transports?: DialTransport[];
    /** Tried first when dialing. Default `'udp'` (or `'tcp'` when only TCP runs). */
    preferredTransport?: DialTransport;
    /**
     * How long the preferred transport dials alone before the other one is raced;
     * a positive integer or `Infinity` (never). Default 1200.
     */
    transportFallbackMs?: number;

    /**
     * Bytes a peer's send queue may hold before a sender that keeps going has the
     * peer dropped (`'slow-consumer'`); `peerWritable()` turns false at a quarter
     * of it. Not a message size limit. Default 0 (8 MiB).
     */
    sendQueueLimit?: number;
    /** How often each peer's path is sampled for `pathStats()`. Default 0: only while an `onPeerPath` handler exists, every 100 ms. */
    pathSampleMs?: number;

    /** Congestion controller of UDP connections. Default `'bbr'`. */
    congestionControl?: CongestionControl;
    /** Ceiling of one UDP connection's flow-control window. Default 0 (16 MiB). */
    udpReceiveWindow?: number;
    /** Bytes all UDP connections together may hold out of order. Default 0 (64 MiB). */
    udpReceiveBudget?: number;
    /** Kernel segmentation offload for UDP where available. Default true. */
    udpOffload?: boolean;

    /** I/O threads. Default 0 (1). */
    reactorThreads?: number;
    /** Watch the host for interface/address changes. Default true. */
    networkMonitor?: boolean;
  }

  export interface PeerInfo {
    /** The wire this connection runs on. */
    transport: Transport;
    /** Transports the peer says it accepts; empty if it did not say. */
    transports: DialTransport[];
    direction: Direction;
    /** Where the peer can be dialed (`'ip:port'` / `'[ip]:port'`), or null until known. */
    address: string | null;
  }

  /**
   * What the transport knows about the path to one peer. Rates are bits per
   * second; `queuedBytes * 8 / bandwidthBps` is how long a new message waits.
   * Over TCP the path figures exist on Linux only; elsewhere, and over a relay,
   * only `queuedBytes` and the live counters are filled.
   */
  export interface PathStats {
    /** The congestion controller's estimate; 0 = none yet. */
    bandwidthBps: number;
    /** The sender was not filling the path, so the estimate is a floor. */
    appLimited: boolean;
    /** Current release rate; 0 = unpaced. */
    pacingBps: number;
    srttUs: number;
    /** Lowest round trip seen: the path without queues. */
    minRttUs: number;
    /** Accepted for the peer, not yet sent. */
    queuedBytes: number;
    /** Sent, not yet acknowledged. */
    bytesInFlight: number;
    /** Share of bytes lost over the last interval, 0..1. */
    loss: number;
    bytesDelivered: number;
    bytesLost: number;
    /** Live messages sent since the connection opened. */
    liveSent: number;
    /** Of those, dropped because their lifetime ran out. */
    liveExpired: number;
    /** Forward-error-correction bytes sent with live messages on a lossy path. */
    liveRepairBytes: number;
  }

  export type FileStatus = 'pending' | 'active' | 'paused' | 'completed' | 'failed' | 'cancelled';

  export interface FileProgress {
    transferId: number;
    peerId: string;
    /** `'outbound'`: we send; `'inbound'`: we receive. */
    direction: Direction;
    status: FileStatus;
    bytesTransferred: number;
    totalBytes: number;
    filesCompleted: number;
    totalFiles: number;
    /** Recent, smoothed. */
    rateBytesPerSec: number;
  }

  export interface Version {
    /** `major.minor.patch.build`, e.g. `'1.2.3.45'` */
    string: string;
    major: number;
    minor: number;
    patch: number;
    build: number;
    /** `git describe` of the build. */
    gitDescribe: string;
    /** `(major << 16) | (minor << 8) | patch` */
    abi: number;
  }

  /**
   * A librats node. Enable subsystems and register callbacks before `start()`;
   * enabling afterwards throws `ALREADY_STARTED`, using a subsystem that was not
   * enabled throws `NOT_ENABLED`. Peer ids are 64-char lowercase hex.
   */
  export class RatsNode {
    constructor(config?: RatsNodeConfig);

    // ---- lifecycle ----

    /** Open the sockets and start the enabled subsystems. Throws `BIND` if the port is taken. */
    start(): void;
    /** Close every connection. Idempotent. */
    stop(): void;
    /**
     * Stop and free the node; further calls throw `DESTROYED`. Registered
     * callbacks keep the process alive until this is called.
     */
    destroy(): void;

    // ---- this node ----

    readonly localId: string;
    readonly protocol: string;
    /** The bound port (the real one when 0 was asked for); 0 before start. */
    readonly listenPort: number;
    /** Transports actually running; empty when stopped. Narrower than asked when a UDP socket could not be bound. */
    readonly transports: DialTransport[];
    readonly natMapping: NatMapping;
    /** Our own addresses as peers report seeing us (`'ip:port'`). */
    readonly observedAddresses: string[];

    // ---- peers ----

    /** Dial a host (literal or name). Throws `NOT_STARTED` before start. Success arrives as `onPeerConnected`, failure as `onDialFailed`. */
    connect(host: string, port: number): void;
    /** @returns false if the peer was not connected. */
    disconnect(peerId: string): boolean;
    readonly peerCount: number;
    readonly peerIds: string[];
    /** null if the peer is not connected. */
    peerInfo(peerId: string): PeerInfo | null;
    /** Cap on established peers (0 = unlimited); can change while running. */
    maxPeers: number;

    // ---- messaging ----

    /**
     * Queue bytes for one peer on a named channel. Throws `NO_SUCH_PEER` if it is
     * not connected. Returning means queued, not delivered — when sending in bulk,
     * check `peerWritable()` after each send.
     *
     * `lifetimeMs` 0 (default) is reliable and ordered. Anything else makes a
     * live message: delivered within that many ms or dropped whole, never partly
     * or twice, ordered with nothing. At most `LIVE_MAX_LIFETIME_MS` (longer is
     * cut) and `LIVE_MAX_PAYLOAD` bytes (larger throws `INVALID_ARG`). For audio
     * and video frames; the receiver needs nothing special.
     */
    send(peerId: string, channel: string, data: string | Buffer, lifetimeMs?: number): void;
    /** `send()` to every connected peer. */
    broadcast(channel: string, data: string | Buffer, lifetimeMs?: number): void;
    /**
     * Whether the peer's send queue has room (false too when it is not
     * connected). False means stop: keep sending and the peer is dropped as
     * `'slow-consumer'`. Resume on `onPeerWritable`.
     */
    peerWritable(peerId: string): boolean;
    /**
     * The latest path sample, or null if the peer is not connected or nothing
     * was sampled yet (sampling needs `pathSampleMs` or an `onPeerPath` handler).
     */
    pathStats(peerId: string): PathStats | null;

    // ---- callbacks (register before start; each call adds a handler) ----

    on(channel: string, handler: (peerId: string, data: Buffer) => void): void;
    onPeerConnected(handler: (peerId: string) => void): void;
    onPeerDisconnected(handler: (peerId: string, reason: CloseReason) => void): void;
    /** A dial to a numeric address failed over every transport (dials by hostname are not reported). */
    onDialFailed(handler: (address: string) => void): void;
    /** A peer whose queue had filled drained back under its mark. */
    onPeerWritable(handler: (peerId: string) => void): void;
    /** A path sample of every peer, every `pathSampleMs` (100 ms if 0). Registering one turns sampling on. */
    onPeerPath(handler: (peerId: string, stats: PathStats) => void): void;

    // ---- discovery (enable before start) ----

    /** Mainline DHT discovery. `discoveryKey` defaults to the protocol, so only nodes that could connect find each other. */
    enableDht(port?: number, discoveryKey?: string): void;
    /** mDNS discovery on the local network. */
    enableMdns(): void;
    /** Peers trade the addresses of peers they hold: one contact is enough to find the rest. */
    enablePeerExchange(): void;

    // ---- NAT traversal (enable before start) ----

    /** Ask the router to forward the listen port over UPnP and/or NAT-PMP. */
    enablePortMapping(upnp?: boolean, natpmp?: boolean): void;
    /**
     * UDP hole punching through a peer both sides share. Every node involved
     * needs it. `serveRendezvous` (default true) also passes other peers'
     * rendezvous along — a few dozen bytes per punch.
     */
    enableHolePunch(serveRendezvous?: boolean): void;
    /**
     * Start a punch; success arrives as `onPeerConnected`. @returns false when
     * declined: already connected, already punching, or no external endpoint of
     * our own known yet.
     */
    punchPeer(peerId: string): boolean;
    /**
     * Relayed connections through a peer both ends share; encryption stays end
     * to end. `serve` (default false) also carries other peers' connections,
     * which costs their bandwidth.
     */
    enableRelay(serve?: boolean): void;
    /**
     * Start a relayed connection; success arrives as `onPeerConnected`.
     * @returns false when declined: already connected, already trying or
     * cooling down, or no connected peer can carry it.
     */
    connectViaRelay(peerId: string): boolean;

    // ---- pub/sub (enable before start) ----

    enablePubsub(): void;
    /** One handler per topic; subscribing again replaces it. */
    subscribe(topic: string, handler: (peerId: string, topic: string, data: Buffer) => void): void;
    unsubscribe(topic: string): void;
    publish(topic: string, data: string | Buffer): void;

    // ---- JSON messaging (enable before start; values are JSON.stringify'd) ----

    enableJson(): void;
    /** Add a handler for messages of `type`; it receives the parsed value. */
    onJson(type: string, handler: (peerId: string, value: any) => void): void;
    /** Like `onJson`, removed after its first message. */
    onceJson(type: string, handler: (peerId: string, value: any) => void): void;
    /** Remove every handler of `type`. */
    offJson(type: string): void;
    sendJson(peerId: string, type: string, value: unknown): void;
    broadcastJson(type: string, value: unknown): void;

    // ---- file transfer (enable before start) ----

    /** `tempDir` holds partial downloads (default `'.'`). */
    enableFileTransfer(tempDir?: string): void;
    /** One handler each, set before start; a second call replaces the first. Answer with `acceptFile` / `rejectFile`. */
    onFileOffer(handler: (peerId: string, transferId: number, name: string, size: number, isDirectory: boolean) => void): void;
    onFileProgress(handler: (progress: FileProgress) => void): void;
    /** `path` is where the data landed (on success). */
    onFileComplete(handler: (peerId: string, transferId: number, success: boolean, path: string) => void): void;
    /**
     * Offer a file to a connected peer. @returns the transfer id. Throws
     * `NO_SUCH_PEER` if the peer is not connected, `NOT_FOUND` if the file cannot be read.
     */
    sendFile(peerId: string, filePath: string): number;
    /** Offer a directory tree; returns and throws as `sendFile`. */
    sendDirectory(peerId: string, dirPath: string): number;
    /** `destPath` is the file to write for a file, the directory to fill for a directory. */
    acceptFile(peerId: string, transferId: number, destPath: string): void;
    rejectFile(peerId: string, transferId: number): void;
    /** @returns false if there is no such transfer. */
    cancelFile(peerId: string, transferId: number): boolean;
    /** @returns false if there is no such transfer. */
    pauseFile(peerId: string, transferId: number): boolean;
    /** @returns false if there is no such transfer. */
    resumeFile(peerId: string, transferId: number): boolean;

    // ---- ping and reconnection (enable before start) ----

    /** Periodic round-trip probing of every peer. */
    enablePing(): void;
    /** Last measured round trip in ms, or null (ping not enabled, no answer yet). */
    peerRttMs(peerId: string): number | null;
    /** Redial dropped peers with backoff; with `dataDir` the list survives restarts. */
    enableReconnect(): void;
    /** Keep an address connected. May be called while running. */
    addReconnect(host: string, port: number): void;
    removeReconnect(host: string, port: number): void;
  }

  export function version(): Version;
  export function setLogLevel(level: LogLevel): void;
  /** Also write logs to `path`; omitted or empty stops file logging. */
  export function setLogFile(path?: string): void;

  /** Longest lifetime of a live message, in ms. */
  export const LIVE_MAX_LIFETIME_MS: number;
  /** Largest payload of a live message, in bytes. */
  export const LIVE_MAX_PAYLOAD: number;
}
