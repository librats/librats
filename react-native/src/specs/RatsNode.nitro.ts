import type { HybridObject } from 'react-native-nitro-modules'

/**
 * Node configuration. Mirrors the subset of `librats::NodeConfig` this slice
 * exposes; every field is optional and falls back to the library default.
 */
export interface RatsConfig {
  /** Port to listen on. 0 (the default) picks an ephemeral port. */
  listenPort?: number
  /**
   * Application protocol id, bound into the Noise handshake. Two nodes whose
   * protocol differs cannot connect, so every platform of the same app must use
   * the identical string. Defaults to librats' own "librats/1.0".
   */
  protocol?: string
  /**
   * Directory for persistent state. When set, the node's keypair — and so its
   * peer id — survives restarts. Pass an app-writable path: on iOS that must be
   * inside the sandbox (Documents or Application Support), and on Android the
   * app's filesDir. Empty (the default) means a fresh identity each run.
   */
  dataDir?: string
  /** false makes a dial-only node that accepts no inbound connections. */
  enableListen?: boolean
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

/**
 * DHT peer discovery. Every field is optional.
 *
 * This joins the BitTorrent Mainline DHT — a real, public, multi-million-node
 * network — and finds peers by announcing under a hash derived from
 * `discoveryKey`. It is plain UDP to other nodes, so unlike mDNS it needs no
 * special iOS entitlement.
 */
export interface DhtConfig {
  /** UDP port for the DHT. 0 (the default) picks an ephemeral one. */
  dhtPort?: number
  /**
   * Where the routing table is persisted, so a restart bootstraps quickly
   * instead of cold. Defaults to the node's `dataDir` when that is set; if
   * neither is set the library falls back to the working directory, which is not
   * writable on mobile — persistence then silently does nothing and every start
   * is a cold bootstrap.
   */
  dataDir?: string
  /** Run the IPv4 Kademlia network. Default true. */
  enableIpv4?: boolean
  /** Run the IPv6 Kademlia network (BEP 32) — a separate DHT. Default true. */
  enableIpv6?: boolean
  /**
   * Namespaces which peers find each other. Empty (the default) uses the node's
   * `protocol`, so peers of the same app version meet and mismatched protocols —
   * which could not handshake anyway — never do.
   */
  discoveryKey?: string
  /**
   * Bootstrap nodes as `"host:port"` (IPv6 as `"[addr]:port"`). Empty uses the
   * built-in public defaults.
   */
  bootstrapNodes?: string[]
  /** How often to search for peers. Default 30000. */
  searchIntervalMs?: number
  /** How often to re-announce. Default 600000; a fresh node announces at once. */
  announceIntervalMs?: number
  /**
   * Probe STUN at startup to learn the public IP and seed the node id per BEP 42.
   * Default true. Without it the node still converges via in-DHT voting, just
   * more slowly.
   */
  discoverExternalIp?: boolean
}

/** A snapshot of the DHT subsystem's state. */
export interface DhtStatus {
  running: boolean
  /** IPv4 DHT UDP port; 0 when not running. */
  port: number
  /** IPv6 DHT UDP port; 0 when not running. */
  portV6: number
  /**
   * The 40-char hex hash this node announces under. **All zeros until
   * `start()`** — it is derived when the subsystem attaches, which happens
   * inside `start()`, and before then the key may not even be known (an empty
   * `discoveryKey` resolves to the node's protocol at that point).
   */
  discoveryHash: string
  /** Public IP used to derive the node id, or '' if not yet known. */
  externalAddress: string
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

/**
 * A librats peer-to-peer node.
 *
 * Create one with `NitroModules.createHybridObject<RatsNode>('RatsNode')`, or use
 * the `createNode()` helper from the package root.
 *
 * Lifecycle: `configure()` (optional) → register listeners → `start()`. Listeners
 * must be registered before `start()`, matching the underlying library: the node
 * dispatches on reactor threads and does not synchronise handler registration
 * against a running node.
 *
 * Every listener is an async Nitro callback, so it is safe for the library to
 * invoke from its own reactor threads — Nitro schedules the JS call onto the JS
 * thread. Listeners must not assume they run synchronously with the native event.
 */
export interface RatsNode
  extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  // --- lifecycle ---

  /**
   * Apply configuration. Must be called before `start()`; throws afterwards.
   * Optional — a node with default configuration is created on first use.
   */
  configure(config: RatsConfig): void

  /** Bind and begin accepting/dialing. False if the listen port could not be bound. */
  start(): boolean

  /** Stop the node. Safe to call when not running; the node can be started again. */
  stop(): void

  readonly isRunning: boolean

  /** The bound port, meaningful once started (0 before). */
  readonly listenPort: number

  /**
   * This node's self-certifying peer id as 64-char hex — it *is* the public key,
   * which is why no PKI is involved in authenticating peers.
   */
  readonly localId: string

  // --- connections ---

  /**
   * Dial a peer. Non-blocking: it returns immediately and the outcome arrives
   * through `onPeerConnected`.
   */
  connect(host: string, port: number): void

  readonly peerCount: number

  /** Peer ids of currently connected peers, as hex. */
  peerIds(): string[]

  // --- messaging ---

  /**
   * Send raw bytes to one peer on a named channel. False if that peer is not
   * connected. The buffer is copied before the call returns, so the caller may
   * reuse or discard it immediately.
   */
  send(peerId: string, channel: string, data: ArrayBuffer): boolean

  /** Send raw bytes to every connected peer on a named channel. */
  broadcast(channel: string, data: ArrayBuffer): void

  /**
   * Handle messages arriving on a channel. One listener per channel; registering
   * a second for the same channel replaces the first.
   *
   * **Must be called before `start()`** and throws otherwise. librats stores
   * channel handlers in an unsynchronized map that reactor threads read on every
   * inbound frame, so registering on a running node is a data race, not a
   * late-but-harmless registration.
   *
   * The ArrayBuffer handed to the listener owns its memory and stays valid for as
   * long as the listener holds it.
   */
  onMessage(
    channel: string,
    listener: (peerId: string, data: ArrayBuffer) => void
  ): void

  // --- peer events ---

  /**
   * **Must be called before `start()`** and throws otherwise -- these append to
   * a plain vector that reactor threads iterate on every peer event.
   *
   * Listeners accumulate: each call adds one, and there is no way to remove it.
   * Register once, at setup, rather than from an effect that can re-run.
   */
  onPeerConnected(listener: (peerId: string) => void): void
  onPeerDisconnected(listener: (peerId: string) => void): void

  // --- file transfer ---
  //
  // Opt-in, like every librats capability: call `enableFileTransfer()` before
  // `start()` or the methods below throw. Files are streamed natively by path —
  // no bytes cross the JS bridge, so a multi-gigabyte transfer costs the JS
  // thread nothing beyond the progress events.

  /**
   * Attach the file-transfer subsystem. Must be called before `start()`, and
   * before any of the methods or listeners below.
   */
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

  /** Control a live transfer from either side. False if no such transfer. */
  pauseTransfer(peerId: string, transferId: number): boolean
  resumeTransfer(peerId: string, transferId: number): boolean
  cancelTransfer(peerId: string, transferId: number): boolean

  transferStats(): TransferStats

  /**
   * An incoming transfer needs a decision. Answer with accept or reject.
   *
   * **Must be called before `start()`** and throws otherwise, like every other
   * `on*` registration here.
   */
  onFileOffer(listener: (offer: FileOffer) => void): void

  /**
   * Progress for transfers in both directions. Fires on the library's own
   * cadence (roughly per progress interval), not per chunk.
   */
  onFileProgress(listener: (progress: FileProgress) => void): void

  /**
   * A transfer finished. `path` is the final destination on the receiving side
   * and the source path on the sending side. Check `success`: a failed integrity
   * check or a disk error also arrives here.
   */
  onFileComplete(
    listener: (transferId: number, success: boolean, path: string) => void
  ): void

  // --- pub/sub (GossipSub) ---
  //
  // Opt-in like file transfer: call `enablePubSub()` before `start()`.
  //
  // This is real GossipSub rather than floodsub — each subscribed topic keeps a
  // bounded mesh, published messages are pushed along it, and a lazy IHAVE/IWANT
  // layer recovers anything missed. Practically that means delivery is
  // best-effort and unordered, and a message may reach you once even though
  // several peers hold it.

  /** Attach the pub/sub subsystem. Must be called before `start()`. */
  enablePubSub(config?: PubSubConfig): void

  /**
   * Subscribe to a topic. One listener per topic; subscribing again to the same
   * topic replaces the previous listener.
   *
   * `topic` names a global namespace shared by every node on your `protocol`, so
   * prefix it if collisions matter. The ArrayBuffer handed to the listener owns
   * its memory and stays valid for as long as the listener holds it.
   */
  subscribe(
    topic: string,
    listener: (peerId: string, topic: string, data: ArrayBuffer) => void
  ): void

  unsubscribe(topic: string): void

  /**
   * Publish to a topic. Goes along the mesh when this node is subscribed,
   * otherwise through a short-lived fanout set.
   *
   * A subscribed publisher **also hears itself**: the local listener fires for
   * this message with `peerId` set to this node's own `localId`. Compare against
   * `localId` if you need to tell your own messages apart from a peer's. A node
   * that is not subscribed has no listener and so sees nothing.
   */
  publish(topic: string, data: ArrayBuffer): void

  isSubscribed(topic: string): boolean
  subscribedTopics(): string[]

  /** Peers that have announced interest in a topic. */
  topicPeers(topic: string): string[]
  /** This node's current mesh for a topic — the subset it exchanges full messages with. */
  meshPeers(topic: string): string[]

  // --- DHT discovery ---
  //
  // Opt-in: call `enableDht()` before `start()`.
  //
  // There is deliberately no `onPeerDiscovered` here, because the subsystem does
  // not hand discovered peers back for you to dial — it dials them itself through
  // the node. Discovery therefore surfaces as ordinary `onPeerConnected` events,
  // and the only thing that distinguishes a DHT-found peer from one you dialled
  // is that you did not call `connect()` for it.
  //
  // Expect this to take time: joining the DHT, announcing, and searching run on
  // their own intervals, so the first discovery typically arrives tens of seconds
  // after `start()` rather than immediately.

  /** Attach DHT discovery. Must be called before `start()`. */
  enableDht(config?: DhtConfig): void

  /**
   * A snapshot of DHT state. Cheap to poll — useful for showing bootstrap
   * progress, since `externalAddress` fills in once STUN or in-DHT voting
   * resolves it.
   */
  dhtStatus(): DhtStatus
}
