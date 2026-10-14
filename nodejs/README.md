# librats — Node.js bindings

Node.js bindings for [librats](../README.md), a C++17 peer-to-peer networking
library. They wrap the librats C API one call to one method; the full reference,
with every option and its default, is [`lib/index.d.ts`](lib/index.d.ts).

## The model

A `RatsNode` is one librats node. By itself it is an encrypted transport —
Noise XX over UDP or TCP, both on one port — with a self-certifying peer id
(64-char hex), manual dialing, and messaging on named channels. Everything else
is opt-in: DHT, mDNS and peer-exchange discovery, port mapping, hole punching,
relaying, pub/sub, JSON messaging, file transfer, ping and reconnection.

- **Enable subsystems and register callbacks before `start()`.** Enabling after
  start throws `ALREADY_STARTED`; using a subsystem that was not enabled throws
  `NOT_ENABLED`.
- **Errors are thrown** as an `Error` whose `code` is `'NOT_ENABLED'`,
  `'NO_SUCH_PEER'`, `'BIND'`, …. Calls that may simply have nothing to act on
  return a boolean instead (`disconnect`, `punchPeer`, `connectViaRelay`,
  `cancelFile`, …), and lookups return `null` (`peerInfo`, `pathStats`,
  `peerRttMs`).
- **Enumerations are strings**: `'udp'`, `'inbound'`, `'slow-consumer'`, ….
- **Callbacks run on the JS thread**, carried over from librats' own threads.
  While a node has callbacks registered it keeps the process alive; `destroy()`
  releases it.

## Installation

```bash
npm install librats
```

This builds librats with CMake and then the addon with node-gyp, so it needs
Node.js 20+, CMake 3.14+ and a C++17 compiler (Visual Studio Build Tools 2017+
on Windows, `build-essential` on Linux, Xcode Command Line Tools on macOS).
[INSTALLATION.md](INSTALLATION.md) describes the build steps.

## Quick start

```javascript
const { RatsNode } = require('librats');

const node = new RatsNode({ listenPort: 8080, dataDir: './state' });

node.onPeerConnected((peerId) => node.send(peerId, 'chat', 'hello'));
node.on('chat', (peerId, data) => console.log(peerId, data.toString()));
node.enableDht();    // find peers on the mainline DHT
node.enableMdns();   // and on the local network

node.start();
console.log(node.localId, 'on port', node.listenPort);
```

`dataDir` keeps the identity (and the DHT routing table) across restarts;
without it the node gets a new peer id every run. `protocol` (default
`'librats/1.0'`) is bound into the handshake — nodes with different protocols
cannot connect, and DHT discovery only finds nodes with the same one.

## Sending

`send(peerId, channel, data, lifetimeMs?)` queues a string or Buffer for one
peer; `broadcast(channel, data, lifetimeMs?)` for all of them. Handlers get a
`Buffer`.

Sending returns as soon as the message is queued. A sender that outruns the
link has the peer dropped with reason `'slow-consumer'`, so a bulk sender
checks `peerWritable(peerId)` after each send and, once it is false, waits for
`onPeerWritable`:

```javascript
function pump(peerId) {
  while (chunks.length) {
    node.send(peerId, 'bulk', chunks.shift());
    if (!node.peerWritable(peerId)) return;   // resume from onPeerWritable
  }
}
node.onPeerWritable(pump);
```

A non-zero `lifetimeMs` makes a **live** message: delivered within that many
ms or dropped whole, never partly or twice, and not ordered with anything.
That suits audio and video frames. The limits are `LIVE_MAX_LIFETIME_MS`
(30 s) and `LIVE_MAX_PAYLOAD` (1 MiB). An encoder can size itself to the path
with `pathStats(peerId)` (bandwidth estimate, round trip, loss, queued bytes,
expired live messages) or with `onPeerPath`.

## Subsystems

| | enable before start | then |
|---|---|---|
| DHT discovery | `enableDht(port?, discoveryKey?)` | |
| mDNS discovery | `enableMdns()` | |
| Peer exchange | `enablePeerExchange()` | |
| Port mapping | `enablePortMapping(upnp?, natpmp?)` | |
| Hole punching | `enableHolePunch(serveRendezvous?)` | `punchPeer(id)`, `natMapping` |
| Relaying | `enableRelay(serve?)` | `connectViaRelay(id)` |
| Pub/sub | `enablePubsub()` | `subscribe`, `unsubscribe`, `publish` |
| JSON messaging | `enableJson()` | `onJson`, `onceJson`, `offJson`, `sendJson`, `broadcastJson` |
| File transfer | `enableFileTransfer(tempDir?)` | `onFileOffer`, `onFileProgress`, `onFileComplete`, `sendFile`, `sendDirectory`, `acceptFile`, `rejectFile`, `cancelFile`, `pauseFile`, `resumeFile` |
| Ping | `enablePing()` | `peerRttMs(id)` |
| Reconnection | `enableReconnect()` | `addReconnect(host, port)`, `removeReconnect(host, port)` |

### Pub/sub and JSON

```javascript
node.enablePubsub();
node.subscribe('lobby', (peerId, topic, data) => console.log(topic, data.toString()));

node.enableJson();
node.onJson('greeting', (peerId, value) => console.log(value.hello));

node.start();
node.publish('lobby', 'hi everyone');
node.broadcastJson('greeting', { hello: 'world' });   // any JSON-serializable value
```

### File transfer

The sender offers; the receiver accepts or rejects. `(peerId, transferId)`
names a transfer on both sides.

```javascript
node.enableFileTransfer('./tmp');   // partial downloads live here
node.onFileOffer((peerId, transferId, name, size, isDirectory) => {
  node.acceptFile(peerId, transferId, `./downloads/${name}`);
});
node.onFileProgress((p) => console.log(p.transferId, p.status, p.bytesTransferred, '/', p.totalBytes));
node.onFileComplete((peerId, transferId, success, path) => console.log(transferId, success, path));
node.start();

const transferId = node.sendFile(peerId, './file.bin');   // throws NO_SUCH_PEER / NOT_FOUND
```

### NAT traversal

Port mapping asks the router to forward the port. Where that fails, hole
punching has a peer both sides share arrange for them to dial each other at
the same moment; every node involved needs it enabled, and at least one must
serve the rendezvous. A symmetric NAT (`natMapping === 'endpoint-dependent'`)
cannot be punched; relaying routes the connection through a shared peer
instead, still encrypted end to end, and `peerInfo(id).transport` reports
`'relay'`. With both enabled, a punch that cannot work falls back to a relay,
and a relayed peer is moved to a direct connection when a later punch succeeds.

```javascript
node.enablePortMapping();
node.enableHolePunch();        // also serves rendezvous for others (default)
node.enableRelay();            // pass true to carry other peers' connections too
node.start();

node.punchPeer(peerId);        // false: declined (already connected, already trying, …)
```

## Examples

```bash
node examples/basic_client.js 8080
node examples/basic_client.js 8081 127.0.0.1 8080
node examples/file_transfer.js 8080
node examples/gossipsub_chat.js 8080 Alice lobby
```

## Testing

```bash
npm test
npm run verify     # load the addon and start a node
```

## License

MIT — see [LICENSE](../LICENSE).
