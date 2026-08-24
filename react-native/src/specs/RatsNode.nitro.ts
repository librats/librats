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
   * The ArrayBuffer handed to the listener owns its memory and stays valid for as
   * long as the listener holds it.
   */
  onMessage(
    channel: string,
    listener: (peerId: string, data: ArrayBuffer) => void
  ): void

  // --- peer events ---

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

  /** An incoming transfer needs a decision. Answer with accept or reject. */
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
}
