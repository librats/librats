/**
 * TypeScript definitions for librats — Node.js bindings.
 *
 * A `RatsNode` is one librats node: secure transport (Noise XX over TCP or the
 * library's reliable stream over UDP), a self-certifying peer id, and raw
 * messaging on named channels. Everything else is an opt-in subsystem enabled
 * BEFORE `start()`.
 */

/// <reference types="node" />

declare module 'librats' {
  /** Transport security selector (`rats_security_t`). */
  export const Security: {
    /** Noise XX, encrypted + authenticated (default). */
    readonly NOISE: 0;
    /** Unencrypted; ids exchanged in the clear. */
    readonly PLAINTEXT: 1;
  };

  /**
   * Which wire a peer connection runs on. TCP and UDP carry the identical protocol
   * and the identical encrypted handshake, and differ only in how the ordered,
   * reliable byte stream underneath is obtained; RELAY is that same stream one hop
   * further away, out of another peer's connection rather than out of a socket.
   */
  export const Transport: {
    /** One kernel socket per peer. */
    readonly TCP: 0;
    /** Reliable stream over the shared UDP socket. */
    readonly UDP: 1;
    /** Carried through a third node (see `enableRelay`). */
    readonly RELAY: 2;
  };

  /**
   * Congestion controller of every UDP stream. BBR holds its rate on lossy links
   * and keeps the bottleneck queue short; Reno backs off on every loss.
   */
  export const Congestion: {
    /** BBRv3 (default). */
    readonly BBR: 0;
    /** NewReno with HyStart++. */
    readonly RENO: 1;
  };

  /** Bitmask flags used by `node.transports` and `node.peerTransports()`. */
  export const TransportMask: {
    readonly TCP: 0x1;
    readonly UDP: 0x2;
  };

  /** What the mesh has shown about this node's own NAT. */
  export const NatMapping: {
    /** Not enough independent observations yet. */
    readonly UNKNOWN: 0;
    /** No NAT in the path. */
    readonly OPEN: 1;
    /** One external port for every peer — punchable. */
    readonly ENDPOINT_INDEPENDENT: 2;
    /** A fresh mapping per peer (symmetric) — not punchable. */
    readonly ENDPOINT_DEPENDENT: 3;
  };

  /** Process-global log levels. */
  export const LogLevel: {
    readonly DEBUG: 0;
    readonly INFO: 1;
    readonly WARN: 2;
    readonly ERROR: 3;
  };

  export type SecurityValue = 0 | 1;
  /** A wire a dial can choose: TCP or UDP. A relay is never dialed. */
  export type TransportValue = 0 | 1;
  export type CongestionValue = 0 | 1;
  /** What a connected peer's link actually runs on, relays included. */
  export type PeerTransportValue = TransportValue | 2;
  export type NatMappingValue = 0 | 1 | 2 | 3;
  export type LogLevelValue = 0 | 1 | 2 | 3;

  /** Full node configuration; mirrors `rats_config_t`. Every field is optional. */
  export interface RatsNodeConfig {
    /** Inbound port shared by both transports; 0 = ephemeral. */
    listenPort?: number;
    /** `false` makes a dial-only node (no listener). Default `true`. */
    enableListen?: boolean;
    /** Bind address; omitted selects the `"::"` dual-stack wildcard. */
    bindAddress?: string;
    /** Default `Security.NOISE`. */
    security?: SecurityValue;
    /** Persistent state dir; omitted gives an ephemeral identity per run. */
    dataDir?: string;
    /** Handshake app id, e.g. `"myapp/1.0"`. Peers whose protocol differs cannot connect. */
    protocol?: string;
    /** Established-peer cap; 0 = unlimited. */
    maxPeers?: number;
    /** Accept and dial over TCP. Default `true`. */
    enableTcp?: boolean;
    /** Accept and dial over the datagram transport. Default `true`. */
    enableUdp?: boolean;
    /** Which transport a dial tries first. Default `Transport.UDP`. */
    preferredTransport?: TransportValue;
    /** Delay before the other transport is raced alongside; 0 disables. Default 1200. */
    transportFallbackMs?: number;
    /**
     * Bytes a peer's send queue may hold before an app that keeps sending anyway
     * has that peer dropped with reason `RATS_CLOSE_SLOW_CONSUMER`. 0 (default)
     * uses the library's 8 MiB. A quarter of it is where `peerWritable()` starts
     * returning false. Not a maximum message size.
     */
    sendQueueLimit?: number;
    /** Congestion controller of every UDP stream. Default `Congestion.BBR`. */
    congestionControl?: CongestionValue;
    /**
     * Bytes one UDP stream will buffer for its peer, at most: the ceiling its
     * receive window grows to while the peer is held back by it. 0 (default)
     * uses the library's 16 MiB.
     */
    udpReceiveWindow?: number;
    /** Bytes all UDP streams together may hold out of order. 0 (default) = 64 MiB. */
    udpReceiveBudget?: number;
    /**
     * How often each connected peer's path is sampled for `pathStats()` and
     * `onPeerPath`, in ms. 0 (default) samples only while an `onPeerPath`
     * handler is registered, and then every 100 ms.
     */
    pathSampleMs?: number;
  }

  /**
   * What the transport knows about the path to one peer. Rates are bits per
   * second; anything past `bandwidthBps` waits in `queuedBytes`, so
   * `queuedBytes * 8 / bandwidthBps` is the wait in seconds.
   */
  export interface PathStats {
    /** The congestion controller's estimate; 0 = none yet. */
    bandwidthBps: number;
    /** The sender was not filling the path, so the estimate is a floor, not the path. */
    appLimited: boolean;
    /** Current release rate; 0 = unpaced. */
    pacingBps: number;
    /** Smoothed round trip, µs. */
    srttUs: number;
    /** Lowest round trip seen — the path without queues, µs. */
    minRttUs: number;
    /** Accepted for the peer, not yet sent. */
    queuedBytes: number;
    /** Sent, not yet acknowledged. */
    bytesInFlight: number;
    /** Share of bytes lost over the last sample interval, 0..1. */
    loss: number;
    /** Acknowledged since the connection opened. */
    bytesDelivered: number;
    /** Declared lost since the connection opened. */
    bytesLost: number;
    /** Live messages (`lifetimeMs` > 0) sent since the connection opened. */
    liveSent: number;
    /**
     * Of those, dropped because their lifetime ran out — the first thing a
     * source asking for more than the path carries will see.
     */
    liveExpired: number;
    /**
     * Bytes of repair symbols (forward error correction) sent with live messages
     * on a lossy path — carried beside the source's own, so a source sized to
     * `bandwidthBps` leaves room for them.
     */
    liveRepairBytes: number;
  }

  export type PeerHandler = (peerId: string) => void;
  /**
   * `reason` is why the peer went — "RATS_CLOSE_PEER_CLOSED",
   * "RATS_CLOSE_SLOW_CONSUMER" and so on. Worth branching on: a peer that left is
   * one to redial, while SLOW_CONSUMER means *you* were sending faster than the
   * link drained, and redialing that one just repeats the overload.
   */
  export type PeerDisconnectHandler = (peerId: string, reason: string) => void;
  export type MessageHandler = (peerId: string, data: Buffer) => void;
  export type PathHandler = (peerId: string, stats: PathStats) => void;
  export type TopicHandler = (peerId: string, topic: string, data: Buffer) => void;
  export type JsonHandler = (peerId: string, value: any) => void;
  export type FileOfferHandler = (
    peerId: string,
    transferId: number,
    name: string,
    size: number,
    isDirectory: boolean
  ) => void;
  export type FileProgressHandler = (
    transferId: number,
    peerId: string,
    bytesTransferred: number,
    totalBytes: number,
    status: number
  ) => void;
  export type FileCompleteHandler = (
    transferId: number,
    peerId: string,
    success: boolean,
    path: string
  ) => void;

  /** Library version components. */
  export interface VersionInfo {
    major: number;
    minor: number;
    patch: number;
    build: number;
  }

  /**
   * A librats node.
   *
   * Enable subsystems and register callbacks BEFORE `start()`. Failures throw an
   * `Error` whose message is `librats: <CODE>`.
   */
  export class RatsNode {
    /**
     * @param portOrConfig listen port (0 = ephemeral) or a config object.
     */
    constructor(portOrConfig?: number | RatsNodeConfig);

    // ---- lifecycle ----

    /** Bring the node up: bind the listener and start enabled subsystems. */
    start(): void;
    /** Tear the node down and close all connections. Idempotent. */
    stop(): void;
    /** Release the native node; the instance is inert afterwards. */
    destroy(): void;

    // ---- identity / info ----

    /** The bound listen port (resolved when 0 was requested). */
    readonly listenPort: number;
    /** Our self-certifying peer id (64-char lowercase hex). */
    readonly localId: string | null;
    /** The app protocol bound into the handshake, e.g. `"librats/1.0"`. */
    readonly protocol: string | null;
    /**
     * Transports actually running, as a `TransportMask` bitmask. May be narrower
     * than the config asked for. 0 before `start()` and after `stop()`.
     */
    readonly transports: number;

    // ---- connections ----

    /** Dial a peer. Non-blocking: success surfaces as `onPeerConnected`. */
    connect(host: string, port: number): void;
    /** Count of currently-connected peers. */
    readonly peerCount: number;
    /** Hex ids of currently-connected peers. */
    readonly peerIds: string[];
    /** Cap on established peers (0 = unlimited). Settable at any time. */
    maxPeers: number;
    /** Which wire a connected peer's link runs on, or `null` if not connected. */
    peerTransport(peerId: string): PeerTransportValue | null;
    /**
     * Transports a connected peer advertised, as a `TransportMask` bitmask, or
     * `null` if not connected. 0 means the peer did not say (an older build).
     */
    peerTransports(peerId: string): number | null;

    // ---- raw channel messaging ----

    /**
     * Send raw bytes on a named channel to one peer. Returning means the message
     * was queued, never that it arrived — if you send in bulk, follow it with
     * `peerWritable()`.
     *
     * `lifetimeMs` 0 (the default) sends reliably. Anything else makes it a live
     * message, worth delivering only within that many milliseconds (30000 at
     * most): repaired while it can still arrive in time, dropped whole once it
     * cannot, never delivered in part or twice, and ordered with nothing. For
     * video and audio frames; at most 1 MiB. The receiver needs nothing new.
     */
    send(peerId: string, channel: string, data: string | Buffer, lifetimeMs?: number): void;
    /** Broadcast raw bytes on a named channel to every connected peer; `lifetimeMs` as for `send()`. */
    broadcast(channel: string, data: string | Buffer, lifetimeMs?: number): void;
    /**
     * Whether this peer's send queue still has room (false also when it is not
     * connected). False means stop: what you just sent was queued like anything
     * else and nothing was dropped, but keep piling on and the peer is dropped
     * with reason `RATS_CLOSE_SLOW_CONSUMER`. Wait for `onPeerWritable`, or poll
     * this. Not a size limit — one message of any size is always queued.
     */
    peerWritable(peerId: string): boolean;
    /**
     * The latest path sample for a peer, or `null` if it is not connected or
     * nothing has been sampled yet — sampling runs only with `pathSampleMs` set
     * or an `onPeerPath` handler registered. Over TCP the figures are the
     * kernel's, on Linux only.
     */
    pathStats(peerId: string): PathStats | null;
    /** Register a handler for a named channel. Additive; register before `start()`. */
    on(channel: string, handler: MessageHandler): void;

    // ---- peer events (register before start) ----

    onPeerConnected(handler: PeerHandler): void;
    onPeerDisconnected(handler: PeerDisconnectHandler): void;
    /** A peer whose queue had filled has drained back under its mark. */
    onPeerWritable(handler: PeerHandler): void;
    /**
     * A path sample of every connected peer, every `pathSampleMs` (100 ms if 0).
     * Registering one turns sampling on. Keep it cheap.
     */
    onPeerPath(handler: PathHandler): void;

    // ---- discovery (enable before start) ----

    /** Enable DHT discovery. `discoveryKey` defaults to the node's protocol. */
    enableDht(dhtPort?: number, discoveryKey?: string): void;
    /** Enable local-network mDNS discovery. */
    enableMdns(): void;

    // ---- NAT traversal (enable before start) ----

    /** Enable automatic NAT port forwarding for the listen port. */
    enablePortMapping(enableUpnp?: boolean, enableNatpmp?: boolean): void;
    /**
     * Enable UDP hole punching. `serveAsRelay` (default `true`) also carries
     * other peers' rendezvous — a mesh in which nobody relays cannot punch.
     */
    enableHolePunch(serveAsRelay?: boolean): void;
    /**
     * Try to reach a peer by punching. Non-blocking: success arrives as an
     * ordinary `onPeerConnected`.
     */
    punchPeer(peerId: string): void;
    /**
     * Enable relaying: reach a peer nothing else could, through a node both ends
     * are already connected to. `serveAsRelay` (default `false`) also carries
     * OTHER peers' connections, which spends real bandwidth.
     */
    enableRelay(serveAsRelay?: boolean): void;
    /**
     * Try to reach a peer through a relay. Non-blocking: success arrives as an
     * ordinary `onPeerConnected`.
     */
    connectViaRelay(peerId: string): void;
    /** A `NatMapping` value describing this node's own NAT. */
    readonly natMapping: NatMappingValue;

    // ---- pub/sub (enable before start) ----

    enablePubsub(): void;
    subscribe(topic: string, handler: TopicHandler): void;
    unsubscribe(topic: string): void;
    publish(topic: string, data: string | Buffer): void;

    // ---- typed JSON messaging (enable before start) ----

    enableJson(): void;
    /** Register an additive handler; the handler receives the parsed value. */
    onJson(type: string, handler: JsonHandler): void;
    /** Like `onJson`, but the handler is removed after it fires once. */
    onceJson(type: string, handler: JsonHandler): void;
    offJson(type: string): void;
    /** `value` is serialized with `JSON.stringify` unless it is already a string. */
    sendJson(peerId: string, type: string, value: any): void;
    broadcastJson(type: string, value: any): void;

    // ---- file transfer (enable + register callbacks before start) ----

    enableFileTransfer(tempDir?: string): void;
    onFileOffer(handler: FileOfferHandler): void;
    onFileProgress(handler: FileProgressHandler): void;
    onFileComplete(handler: FileCompleteHandler): void;
    /** @returns the transfer id, or 0 on failure. */
    sendFile(peerId: string, filePath: string): number;
    /** @returns the transfer id, or 0 on failure. */
    sendDirectory(peerId: string, dirPath: string): number;
    /** `destPath` is the file path for a single file, else the destination directory. */
    acceptFile(peerId: string, transferId: number, destPath: string): void;
    rejectFile(peerId: string, transferId: number): void;
    cancelFile(peerId: string, transferId: number): void;
    pauseFile(peerId: string, transferId: number): void;
    resumeFile(peerId: string, transferId: number): void;

    // ---- liveness / reconnection (enable before start) ----

    enablePing(): void;
    /** Last measured RTT in ms, or -1 if unknown. */
    peerRttMs(peerId: string): number;
    enableReconnect(): void;
    addReconnect(host: string, port: number): void;
    removeReconnect(host: string, port: number): void;
  }

  // ---- library info (process-global) ----

  /** Library version as a string, e.g. `"1.2.3"`. */
  export function version(): string;
  /** Library version components. */
  export function versionInfo(): VersionInfo;
  /** Git describe of the build, e.g. `"v1.2.3-4-gabcdef"`. */
  export function gitDescribe(): string;
  /** Packed ABI id as `(major << 16) | (minor << 8) | patch`. */
  export function abi(): number;

  // ---- process-global logging ----

  export function setLogLevel(level: LogLevelValue): void;
  /** Mirror logs to a file; omitted/empty disables file logging. */
  export function setLogFile(path?: string): void;
}
