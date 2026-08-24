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
}
