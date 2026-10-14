/**
 * librats — Node.js bindings.
 *
 * A `RatsNode` is one librats node: an encrypted transport (Noise XX over UDP
 * or TCP) with a self-certifying peer id and messaging on named channels.
 * Discovery, NAT traversal, pub/sub, JSON messaging, file transfer, ping and
 * reconnection are opt-in and must be enabled before `start()`.
 *
 * Enumerations are lowercase strings ('udp', 'slow-consumer', …). Failures throw
 * an `Error` whose `code` names the cause ('NOT_ENABLED', 'NO_SUCH_PEER', …).
 * Callbacks are registered before `start()` and run on the JS thread.
 */

'use strict';

const path = require('path');
const fs = require('fs');

const candidates = [
  path.join(__dirname, '..', 'build', 'Release', 'librats.node'),
  path.join(__dirname, '..', 'build', 'Debug', 'librats.node'),
];
const addonPath = candidates.find((p) => fs.existsSync(p));
if (!addonPath) {
  throw new Error(
    'librats: the native addon is not built (looked in build/Release and build/Debug). ' +
    'Run `npm rebuild librats`.'
  );
}
const addon = require(addonPath);

/**
 * A librats node.
 *
 * ```js
 * const { RatsNode } = require('librats');
 * const node = new RatsNode({ listenPort: 8080, dataDir: './state' });
 * node.onPeerConnected((id) => console.log('peer', id));
 * node.on('chat', (id, data) => console.log(id, data.toString()));
 * node.enableDht();
 * node.start();
 * ```
 */
class RatsNode {
  /** @param {import('librats').RatsNodeConfig} [config] every field optional */
  constructor(config) {
    this._native = new addon.RatsNode(config);
  }

  // ---- lifecycle ----

  start() { this._native.start(); }
  stop() { this._native.stop(); }
  /**
   * Stop the node and free it. Registered callbacks keep the process alive
   * until this is called (or the node is garbage collected).
   */
  destroy() { this._native.destroy(); }

  // ---- this node ----

  get localId() { return this._native.localId(); }
  get protocol() { return this._native.protocol(); }
  get listenPort() { return this._native.listenPort(); }
  get transports() { return this._native.transports(); }
  get natMapping() { return this._native.natMapping(); }
  get observedAddresses() { return this._native.observedAddresses(); }

  // ---- peers ----

  connect(host, port) { this._native.connect(host, port); }
  disconnect(peerId) { return this._native.disconnect(peerId); }
  get peerCount() { return this._native.peerCount(); }
  get peerIds() { return this._native.peerIds(); }
  peerInfo(peerId) { return this._native.peerInfo(peerId); }
  get maxPeers() { return this._native.maxPeers(); }
  set maxPeers(n) { this._native.setMaxPeers(n); }

  // ---- messaging ----

  send(peerId, channel, data, lifetimeMs) { this._native.send(peerId, channel, data, lifetimeMs); }
  broadcast(channel, data, lifetimeMs) { this._native.broadcast(channel, data, lifetimeMs); }
  peerWritable(peerId) { return this._native.peerWritable(peerId); }
  pathStats(peerId) { return this._native.pathStats(peerId); }

  // ---- callbacks (register before start) ----

  on(channel, handler) { this._native.on(channel, handler); }
  onPeerConnected(handler) { this._native.onPeerConnected(handler); }
  onPeerDisconnected(handler) { this._native.onPeerDisconnected(handler); }
  onDialFailed(handler) { this._native.onDialFailed(handler); }
  onPeerWritable(handler) { this._native.onPeerWritable(handler); }
  onPeerPath(handler) { this._native.onPeerPath(handler); }

  // ---- discovery and NAT traversal (enable before start) ----

  enableDht(port = 0, discoveryKey) { this._native.enableDht(port, discoveryKey); }
  enableMdns() { this._native.enableMdns(); }
  enablePeerExchange() { this._native.enablePeerExchange(); }
  enablePortMapping(upnp = true, natpmp = true) { this._native.enablePortMapping(upnp, natpmp); }
  enableHolePunch(serveRendezvous = true) { this._native.enableHolePunch(serveRendezvous); }
  punchPeer(peerId) { return this._native.punchPeer(peerId); }
  enableRelay(serve = false) { this._native.enableRelay(serve); }
  connectViaRelay(peerId) { return this._native.connectViaRelay(peerId); }

  // ---- pub/sub ----

  enablePubsub() { this._native.enablePubsub(); }
  subscribe(topic, handler) { this._native.subscribe(topic, handler); }
  unsubscribe(topic) { this._native.unsubscribe(topic); }
  publish(topic, data) { this._native.publish(topic, data); }

  // ---- JSON messaging: values in, values out ----

  enableJson() { this._native.enableJson(); }
  onJson(type, handler) { this._native.onJson(type, parsed(handler)); }
  onceJson(type, handler) { this._native.onceJson(type, parsed(handler)); }
  offJson(type) { this._native.offJson(type); }
  sendJson(peerId, type, value) { this._native.sendJson(peerId, type, stringify(value)); }
  broadcastJson(type, value) { this._native.broadcastJson(type, stringify(value)); }

  // ---- file transfer ----

  enableFileTransfer(tempDir) { this._native.enableFileTransfer(tempDir); }
  onFileOffer(handler) { this._native.onFileOffer(handler); }
  onFileProgress(handler) { this._native.onFileProgress(handler); }
  onFileComplete(handler) { this._native.onFileComplete(handler); }
  sendFile(peerId, filePath) { return this._native.sendFile(peerId, filePath); }
  sendDirectory(peerId, dirPath) { return this._native.sendDirectory(peerId, dirPath); }
  acceptFile(peerId, transferId, destPath) { this._native.acceptFile(peerId, transferId, destPath); }
  rejectFile(peerId, transferId) { this._native.rejectFile(peerId, transferId); }
  cancelFile(peerId, transferId) { return this._native.cancelFile(peerId, transferId); }
  pauseFile(peerId, transferId) { return this._native.pauseFile(peerId, transferId); }
  resumeFile(peerId, transferId) { return this._native.resumeFile(peerId, transferId); }

  // ---- ping and reconnection ----

  enablePing() { this._native.enablePing(); }
  peerRttMs(peerId) { return this._native.peerRttMs(peerId); }
  enableReconnect() { this._native.enableReconnect(); }
  addReconnect(host, port) { this._native.addReconnect(host, port); }
  removeReconnect(host, port) { this._native.removeReconnect(host, port); }
}

// The C API carries JSON text; JS callers deal in values.
function stringify(value) {
  const text = JSON.stringify(value);
  if (text === undefined) throw new TypeError('librats: value is not representable as JSON');
  return text;
}

function parsed(handler) {
  if (typeof handler !== 'function') return handler;   // let the addon report it
  return (peerId, text) => handler(peerId, JSON.parse(text));
}

module.exports = {
  RatsNode,
  version: addon.version,
  setLogLevel: addon.setLogLevel,
  setLogFile: addon.setLogFile,
  LIVE_MAX_LIFETIME_MS: addon.LIVE_MAX_LIFETIME_MS,
  LIVE_MAX_PAYLOAD: addon.LIVE_MAX_PAYLOAD,
};
