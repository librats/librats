import type { HybridObject } from 'react-native-nitro-modules'

// ─── enumerations ───────────────────────────────────────────────────────────

/** A wire a dial can use. Both carry the same protocol under the same encrypted handshake. */
export type Transport = 'udp' | 'tcp'

/** What a connected peer's link runs on: a wire, or carried through a relay. */
export type PeerTransport = 'udp' | 'tcp' | 'relay'

export type Security = 'noise' | 'plaintext'

/** Congestion controller of every UDP connection; TCP is the kernel's. */
export type CongestionControl = 'bbr' | 'reno'

/** Who dialed: 'outbound' means this node did. */
export type PeerDirection = 'outbound' | 'inbound'

/**
 * What the mesh has shown about this node's NAT, from where UDP peers report
 * seeing it. 'endpoint_dependent' (symmetric NAT) means hole punching cannot
 * work from here.
 */
export type NatMapping =
  | 'unknown'
  | 'open'
  | 'endpoint_independent'
  | 'endpoint_dependent'

/**
 * Why a peer connection ended. 'slow_consumer' is the one the app causes: it
 * kept sending while the peer's queue was past its limit (see `peerWritable()`),
 * and redialing without slowing down repeats it. 'local' is this node's own
 * `disconnect()`; 'duplicate_connection' and 'dial_superseded' are a second
 * connection to the same peer being folded into the first.
 */
export type CloseReason =
  | 'local'
  | 'peer_closed'
  | 'peer_reset'
  | 'connect_failed'
  | 'handshake_failed'
  | 'protocol_error'
  | 'slow_consumer'
  | 'shutdown'
  | 'duplicate_connection'
  | 'peer_limit'
  | 'idle_timeout'
  | 'dial_superseded'

// ─── configuration ──────────────────────────────────────────────────────────

/**
 * Node configuration, mirroring `librats::NodeConfig`. Every field is optional
 * and falls back to the library default.
 */
export interface RatsConfig {
  /** Port both transports listen on. 0 (the default) picks an ephemeral one. */
  listenPort?: number
  /**
   * Interface to listen on. Default "::", every interface over IPv6 and IPv4.
   * "0.0.0.0" is IPv4 only; a literal address binds that interface alone.
   */
  bindAddress?: string
  /** true makes a node that only dials out and accepts no inbound connections. */
  dialOnly?: boolean
  /**
   * Application protocol id, bound into the Noise handshake. Two nodes whose
   * protocol differs cannot connect, so every platform of the same app must use
   * the identical string. Defaults to "librats/1.0".
   */
  protocol?: string
  /**
   * Directory for persistent state. When set, the node's keypair — and so its
   * peer id — survives restarts, and the DHT and reconnection subsystems keep
   * their state there too. Pass an app-writable path: on iOS that must be inside
   * the sandbox (Documents or Application Support), on Android the app's
   * filesDir. Unset means a new identity every run.
   */
  dataDir?: string
  /** Default 'noise'. 'plaintext' sends everything in the clear. */
  security?: Security
  /** Cap on established peers, enforced on inbound. 0 (the default) is unlimited. */
  maxPeers?: number

  /** Transports to run. Default both; an empty list is refused. */
  transports?: Transport[]
  /**
   * Which transport a dial tries first. Default 'udp' — one socket and one NAT
   * mapping for every peer, which is also what makes hole punching possible.
   */
  preferredTransport?: Transport
  /**
   * How long the preferred transport dials alone before the other is raced
   * alongside it. Default 1200; 0 never races.
   */
  transportFallbackMs?: number

  /**
   * Bytes a peer's send queue may hold before a sender that keeps going has the
   * peer dropped with 'slow_consumer'. `peerWritable()` turns false at a quarter
   * of it. Not a message size limit. Default 8 MiB.
   */
  sendQueueLimit?: number
  /**
   * How often each peer's path is sampled for `pathStats()`. Default 0: only
   * while an `onPeerPath` listener is registered, and then every 100 ms.
   */
  pathSampleMs?: number

  /** Default 'bbr', which holds its rate through loss that is not congestion. */
  congestionControl?: CongestionControl
  /**
   * Ceiling one UDP connection's flow-control window grows to (it starts at
   * 1 MiB); throughput is bounded by window / round trip. Default 16 MiB.
   */
  udpReceiveWindow?: number
  /** Bytes all UDP connections together may hold out of order. Default 64 MiB. */
  udpReceiveBudget?: number
  /** Kernel segmentation offload for UDP where the OS has it. Default true. */
  udpOffload?: boolean

  /** I/O threads. Default 1, which is plenty for a phone. */
  reactorThreads?: number
  /**
   * Watch the device for interface and address changes (Wi-Fi to cellular and
   * back) so subsystems can react. Default true; costs one mostly idle thread.
   */
  networkMonitor?: boolean
}

/** DHT discovery options. */
export interface DhtConfig {
  /** UDP port of the DHT. 0 (the default) picks an ephemeral one. */
  port?: number
  /**
   * Namespace announced and searched on the mainline DHT. Defaults to the
   * node's `protocol`, so only nodes that could handshake find each other.
   */
  discoveryKey?: string
}

/** Port mapping backends; both default to true and run in parallel. */
export interface PortMappingConfig {
  upnp?: boolean
  natpmp?: boolean
}

/**
 * File-transfer configuration. Mirrors the subset of
 * `librats::FileTransfer::Config` this binding exposes.
 */
export interface FileTransferConfig {
  /**
   * Where in-progress downloads are written before being verified and moved to
   * their destination. **Required**, because the library default (".") is the
   * process working directory, which is not writable on either mobile platform.
   * Use a cache path — the app's Caches directory on iOS, `cacheDir` on Android.
   */
  tempDirectory: string
  /** Payload bytes per chunk. Default 65536. */
  chunkSize?: number
  /** Maximum un-acked bytes in flight; the backpressure window. Default 4 MiB. */
  windowBytes?: number
  /** Abort a transfer that has been idle this long. Default 60. */
  transferTimeoutSecs?: number
  /** Whole-file SHA-256 check end to end. Default true; turning it off is unwise. */
  verifyIntegrity?: boolean
}

/**
 * GossipSub tuning. Every field is optional; the defaults mirror the libp2p
 * reference (D=6, D_low=4, D_high=12) and suit small-to-medium meshes.
 */
export interface PubSubConfig {
  /** D — desired mesh degree per topic. Default 6. */
  meshTarget?: number
  /** D_low — graft more peers below this. Default 4. */
  meshLow?: number
  /** D_high — prune peers above this. Default 12. */
  meshHigh?: number
  /** Peers used to publish to a topic this node is not subscribed to. Default 6. */
  fanoutSize?: number
  /** D_lazy — peers sent IHAVE per heartbeat per topic. Default 6. */
  gossipFactor?: number
  /** Mesh maintenance and gossip cadence. Default 1000. */
  heartbeatIntervalMs?: number
  /** How many message ids are remembered for deduplication. Default 8192. */
  seenLimit?: number
}

// ─── values handed to and from the node ─────────────────────────────────────

/** A connected peer, as this node sees it. */
export interface PeerInfo {
  transport: PeerTransport
  /** Transports the peer says it accepts; empty if it did not say. */
  transports: Transport[]
  direction: PeerDirection
  /** Where the peer can be dialed, "ip:port" or "[ip]:port"; empty until known. */
  addresses: string[]
}

/**
 * What the transport knows about the path to one peer, for a sender that sizes
 * its output to the path (a live encoder). Rates are bits per second. A new
 * message waits behind `queuedBytes`; `queuedBytes * 8 / bandwidthBps` is that
 * wait in seconds. Over TCP the path figures are the kernel's and exist on
 * Linux (so Android) only; on iOS TCP, and over a relay, only `queuedBytes` and
 * the live counters are filled.
 */
export interface PathStats {
  /** The congestion controller's estimate; 0 until there is one. */
  bandwidthBps: number
  /** The sender was not filling the path, so `bandwidthBps` is a floor. */
  appLimited: boolean
  /** Current release rate; 0 when unpaced. */
  pacingBps: number
  /** Smoothed round trip, microseconds. */
  srttUs: number
  /** Lowest round trip seen — the path without queues, microseconds. */
  minRttUs: number
  /** Accepted for the peer, not yet sent. */
  queuedBytes: number
  /** Sent, not yet acknowledged. */
  bytesInFlight: number
  /** Share of bytes lost over the last sample interval, 0..1. */
  loss: number
  /** Acknowledged since the connection opened. */
  bytesDelivered: number
  /** Declared lost since the connection opened. */
  bytesLost: number
  /** Live messages (`lifetimeMs` > 0) sent since the connection opened. */
  liveSent: number
  /** Of those, dropped because their lifetime ran out. */
  liveExpired: number
  /** Forward-error-correction bytes sent with live messages on a lossy path. */
  liveRepairBytes: number
}

/** One file inside a transfer. A single-file transfer has exactly one. */
export interface FileEntry {
  /** POSIX path relative to the transfer root. */
  relativePath: string
  size: number
}

/**
 * An incoming transfer awaiting a decision. Answer every offer with either
 * `acceptFile()` or `rejectFile()` — an ignored offer occupies the sender until
 * it times out.
 *
 * Treat `name` and every `files[].relativePath` as untrusted: they come from the
 * peer. The library validates manifest paths against traversal before writing,
 * but if you build a UI or a destination path from them, sanitise them yourself.
 */
export interface FileOffer {
  peerId: string
  transferId: number
  /** File or directory name as the sender declared it. Untrusted. */
  name: string
  /** Total bytes across all files. */
  size: number
  isDirectory: boolean
  files: FileEntry[]
}

export type TransferDirection = 'sending' | 'receiving'

export type TransferStatus =
  | 'pending'
  | 'active'
  | 'paused'
  | 'completed'
  | 'failed'
  | 'cancelled'

/** A progress snapshot, delivered for transfers in both directions. */
export interface FileProgress {
  transferId: number
  peerId: string
  direction: TransferDirection
  status: TransferStatus
  bytesTransferred: number
  totalBytes: number
  filesCompleted: number
  totalFiles: number
  /** Completion in [0, 100], precomputed from the byte counts. */
  percent: number
  /** Recent smoothed throughput, bytes/sec. */
  transferRateBps: number
  /** Mean throughput since the transfer went live, bytes/sec. */
  averageRateBps: number
  /** Time since the transfer went live. */
  elapsedMs: number
  /** ETA at the recent rate. 0 means unknown. */
  etaMs: number
}

/** Aggregate counters since the node started. */
export interface TransferStats {
  bytesSent: number
  bytesReceived: number
  completed: number
  failed: number
}

// ─── the node ───────────────────────────────────────────────────────────────

/**
 * A librats peer-to-peer node.
 *
 * Create one with the `createNode()` helper from the package root (or
 * `NitroModules.createHybridObject<RatsNode>('RatsNode')` plus `configure()`).
 *
 * Order: `configure()` → `enable*()` the subsystems you want → register
 * listeners → `start()`. Enabling a subsystem and registering an event listener
 * after `start()` throws: the library reads those tables from its reactor
 * threads without a lock. The exceptions, safe on a running node, are
 * `subscribe()` / `unsubscribe()` and the JSON `onJson()` / `onceJson()` /
 * `offJson()`.
 *
 * Every listener is an async Nitro callback: the library calls it on a reactor
 * thread and Nitro runs it on the JS thread, later. Do not assume it runs
 * synchronously with the native event.
 */
export interface RatsNode
  extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  // ─── lifecycle ───

  /**
   * Apply configuration. Must come first — before `start()`, any `enable*()`
   * and any listener — and throws otherwise, because the library fixes its
   * configuration when the node is constructed. Optional: without it the node
   * is built with the defaults on first use.
   */
  configure(config: RatsConfig): void

  /** Open the sockets and start every enabled subsystem. False if the listen port could not be bound. */
  start(): boolean

  /** Stop the node and close every connection. Safe to call when not running. */
  stop(): void

  readonly isRunning: boolean

  // ─── this node ───

  /** The bound port, meaningful once started (0 before). */
  readonly listenPort: number

  /**
   * This node's self-certifying peer id as 64-char hex — it *is* the public
   * key, which is why no PKI is involved in authenticating peers.
   */
  readonly localId: string

  /** The protocol bound into the handshake. */
  readonly protocol: string

  /**
   * Transports actually running. Can be narrower than configured: a UDP socket
   * that cannot be bound leaves the node TCP-only rather than failing. Empty
   * when not running.
   */
  readonly transports: Transport[]

  /** See `NatMapping`. Starts 'unknown' and settles as UDP peers report in. */
  readonly natMapping: NatMapping

  /** This node's own addresses as peers report seeing it ("ip:port"). */
  observedAddresses(): string[]

  // ─── peers ───

  /**
   * Dial host:port (a literal or a hostname). Non-blocking: success arrives as
   * `onPeerConnected`, failure as `onDialFailed`.
   */
  connect(host: string, port: number): void

  /** Close the connection to a peer. False if it is not connected. */
  disconnect(peerId: string): boolean

  readonly peerCount: number

  /** Ids of the connected peers, as hex. */
  peerIds(): string[]

  /** What the node knows about a connected peer; undefined if not connected. */
  peerInfo(peerId: string): PeerInfo | undefined

  /** Cap on established peers (0 = unlimited). Can be changed while running. */
  maxPeers: number

  // ─── messaging ───

  /**
   * Send raw bytes to one peer on a named channel. The buffer is copied before
   * the call returns.
   *
   * Without `lifetimeMs` (or with 0) the message is reliable: it arrives, in
   * order with everything else this node sends on its channels. With a lifetime
   * it is a live message, worth delivering only within that many ms (30000 at
   * most): repaired while it can still arrive in time, dropped whole once it
   * cannot, never delivered partly or twice, and ordered with nothing — number
   * them if order matters. Made for audio and video frames; at most 1 MiB. The
   * receiver needs nothing special.
   *
   * False means the peer is not connected or its queue is out of room — in the
   * second case the message was still queued, and false asks you to pause (see
   * `peerWritable()`).
   */
  send(peerId: string, channel: string, data: ArrayBuffer, lifetimeMs?: number): boolean

  /**
   * `send()` to every connected peer. False when any of them is out of room —
   * a fan-out is paced by its slowest recipient.
   */
  broadcast(channel: string, data: ArrayBuffer, lifetimeMs?: number): boolean

  /**
   * Whether this peer's send queue still has room; false also for a peer that
   * is not connected. False means stop: what you sent was queued and nothing
   * was dropped, but keep going and the peer is dropped with 'slow_consumer'.
   * Wait for `onPeerWritable`, or poll this. Not a size limit — one message of
   * any size is always queued.
   */
  peerWritable(peerId: string): boolean

  /**
   * The latest path sample for a peer; undefined if it is not connected or
   * nothing was sampled yet (sampling needs `pathSampleMs` or an `onPeerPath`
   * listener).
   */
  pathStats(peerId: string): PathStats | undefined

  /**
   * Messages arriving on a channel. One listener per channel; a second one for
   * the same channel replaces the first. The ArrayBuffer owns its memory.
   */
  onMessage(
    channel: string,
    listener: (peerId: string, data: ArrayBuffer) => void
  ): void

  // ─── peer events ───
  //
  // Listeners accumulate: each call adds one and none can be removed, so
  // register once at setup, not from an effect that can re-run.

  onPeerConnected(listener: (peerId: string) => void): void

  onPeerDisconnected(listener: (peerId: string, reason: CloseReason) => void): void

  /**
   * A dial to a numeric address failed over every transport tried — one made
   * by `connect()` or by a discovery subsystem. A dial by hostname is not
   * reported.
   */
  onDialFailed(listener: (address: string) => void): void

  /**
   * A peer whose queue had filled has drained back under its mark — the other
   * half of `peerWritable()` returning false.
   */
  onPeerWritable(listener: (peerId: string) => void): void

  /**
   * A path sample of every connected peer, every `pathSampleMs` (100 ms if 0).
   * Registering one turns sampling on. Each sample crosses to the JS thread, so
   * prefer `pathStats()` when you only need the figures now and then.
   */
  onPeerPath(listener: (peerId: string, stats: PathStats) => void): void

  // ─── discovery (enable before start) ───

  /** Find peers on the mainline DHT, announcing and searching `discoveryKey`. */
  enableDht(config?: DhtConfig): void

  /**
   * Find peers on the local network over mDNS. On iOS 14+ raw multicast needs
   * the com.apple.developer.networking.multicast entitlement.
   */
  enableMdns(): void

  /**
   * Peer exchange: connected peers trade the addresses of peers they hold, so
   * one contact is enough to find the rest of the mesh.
   */
  enablePeerExchange(): void

  // ─── NAT traversal (enable before start) ───

  /** Ask the router to forward the listen port (UPnP IGD and/or NAT-PMP). */
  enablePortMapping(config?: PortMappingConfig): void

  /**
   * UDP hole punching: reach a peer behind a NAT by having a peer both sides
   * share arrange for the two to dial each other at once. Every node involved
   * needs it enabled. `serveRendezvous` (default true) also passes other peers'
   * rendezvous along — a few dozen bytes per punch; a mesh where nobody does
   * this cannot punch.
   */
  enableHolePunch(serveRendezvous?: boolean): void

  /**
   * Start punching to a peer. Success arrives as `onPeerConnected`. False when
   * there is nothing to do or nothing to try with: already connected, already
   * punching, or no external endpoint of this node's own known yet.
   */
  punchPeer(peerId: string): boolean

  /**
   * Relaying: reach a peer nothing else can, through a node both ends are
   * connected to. Encryption stays end to end; `peerInfo()` reports 'relay'.
   * `serve` (default false) also carries other peers' connections, at the cost
   * of their bandwidth — rarely what a phone wants. With hole punching enabled
   * too, a failed punch falls back to a relay by itself.
   */
  enableRelay(serve?: boolean): void

  /**
   * Start a relayed connection to a peer. Success arrives as `onPeerConnected`.
   * False when already connected, already trying or cooling down, or no
   * connected peer can carry it.
   */
  connectViaRelay(peerId: string): boolean

  // ─── JSON messaging ───
  //
  // Typed messages carrying a JSON document. JSON crosses this boundary as text:
  // `JSON.stringify` what you send and `JSON.parse` what you receive.

  /** Enable before `start()`. */
  enableJson(): void

  /** Add a listener for messages of `type`. Safe on a running node. */
  onJson(type: string, listener: (peerId: string, json: string) => void): void

  /** Like `onJson`; the listener is removed after its first message. */
  onceJson(type: string, listener: (peerId: string, json: string) => void): void

  /** Remove every listener of `type`. */
  offJson(type: string): void

  /** Throws if `json` is not valid JSON. False if the peer is not connected. */
  sendJson(peerId: string, type: string, json: string): boolean

  /** Throws if `json` is not valid JSON. */
  broadcastJson(type: string, json: string): void

  // ─── file transfer ───
  //
  // Files are streamed natively by path — no bytes cross the JS bridge, so a
  // multi-gigabyte transfer costs the JS thread nothing beyond the progress
  // events.

  /** Enable before `start()`, and before any of the methods below. */
  enableFileTransfer(config: FileTransferConfig): void

  /**
   * Offer a single file to a peer. Returns the transfer id, or 0 if the file
   * cannot be read. Non-blocking: the offer goes out and the peer decides.
   */
  sendFile(peerId: string, path: string): number

  /** Offer a directory tree, sent recursively as one transfer. 0 on failure. */
  sendDirectory(peerId: string, path: string): number

  /**
   * Accept an offered transfer. For a single file `destPath` is the destination
   * file path; for a directory it is the destination directory. Data lands in a
   * temp file and is moved into place only after its SHA-256 verifies.
   */
  acceptFile(peerId: string, transferId: number, destPath: string): void

  /** Decline an offered transfer. */
  rejectFile(peerId: string, transferId: number): void

  /** Control a running transfer from either side. False if no such transfer. */
  pauseTransfer(peerId: string, transferId: number): boolean
  resumeTransfer(peerId: string, transferId: number): boolean
  cancelTransfer(peerId: string, transferId: number): boolean

  transferStats(): TransferStats

  /** An incoming transfer needs a decision. One listener; a second replaces it. */
  onFileOffer(listener: (offer: FileOffer) => void): void

  /**
   * Progress for transfers in both directions, on the library's own cadence
   * rather than per chunk. One listener; a second replaces it.
   */
  onFileProgress(listener: (progress: FileProgress) => void): void

  /**
   * A transfer finished. `path` is the final destination on the receiving side
   * and the source path on the sending side. Check `success`: a failed
   * integrity check or a disk error also arrives here. One listener; a second
   * replaces it.
   */
  onFileComplete(
    listener: (
      transferId: number,
      peerId: string,
      success: boolean,
      path: string
    ) => void
  ): void

  // ─── pub/sub (GossipSub) ───
  //
  // Each subscribed topic keeps a bounded mesh, published messages are pushed
  // along it, and a lazy IHAVE/IWANT layer recovers anything missed. Delivery is
  // best-effort and unordered.

  /** Enable before `start()`. */
  enablePubSub(config?: PubSubConfig): void

  /**
   * Subscribe to a topic. One listener per topic; subscribing again replaces
   * it. Safe on a running node.
   *
   * `topic` names a namespace shared by every node on your `protocol`, so
   * prefix it if collisions matter. The ArrayBuffer owns its memory.
   */
  subscribe(
    topic: string,
    listener: (peerId: string, topic: string, data: ArrayBuffer) => void
  ): void

  unsubscribe(topic: string): void

  /**
   * Publish to a topic: along the mesh when this node is subscribed, otherwise
   * through a short-lived fanout set.
   *
   * A subscribed publisher **also hears itself**: its listener fires with
   * `peerId` set to this node's own `localId`.
   */
  publish(topic: string, data: ArrayBuffer): void

  isSubscribed(topic: string): boolean
  subscribedTopics(): string[]

  /** Peers that have announced interest in a topic. */
  topicPeers(topic: string): string[]
  /** This node's current mesh for a topic — the peers it exchanges full messages with. */
  meshPeers(topic: string): string[]

  // ─── ping and reconnection (enable before start) ───

  /** Probe every peer's round trip periodically. */
  enablePing(): void

  /**
   * Last measured round trip to a peer in ms; undefined until a probe has been
   * answered. (`pathStats().srttUs` has the transport's own figure without any
   * probing.)
   */
  peerRttMs(peerId: string): number | undefined

  /**
   * Redial dropped peers with exponential backoff. Every address dialed is
   * remembered; with `dataDir` the list survives restarts.
   */
  enableReconnect(): void

  /** Keep host:port connected. Throws if the host does not resolve. */
  addReconnect(host: string, port: number): void

  /** Stop keeping host:port connected and forget it. */
  removeReconnect(host: string, port: number): void
}
