# librats — Node.js bindings

Node.js bindings for [librats](../README.md), a C++17 peer-to-peer networking
library: encrypted transport, DHT/mDNS discovery, NAT traversal, pub/sub, typed
JSON messaging and file transfer.

## The model

A `RatsNode` is one librats node. On its own it gives you secure transport
(Noise XX over TCP **or** the library's reliable stream over UDP, both on the
same port), a self-certifying peer id, manual dialing, and raw messaging on named
channels — nothing else. Discovery, pub/sub, JSON messaging, file transfer, NAT
port mapping, hole punching, RTT probing and reconnection are **opt-in
subsystems**: you pay only for what you turn on.

Two rules follow from that:

- **Enable subsystems and register callbacks before `start()`.** Enabling after
  start throws `RATS_ERR_ALREADY_STARTED`; using a subsystem before its enable
  throws `RATS_ERR_NOT_ENABLED`.
- **Callbacks are marshalled onto the JS thread** from a librats reactor thread.
  Keep them short anyway — a slow handler backs up the reactor's queue.

Fallible calls **throw** an `Error` whose message is `librats: <CODE>`; pure
getters are properties.

## Installation

```bash
npm install librats
```

The install builds the native librats library with CMake, then compiles the
Node.js addon against it. You need:

- **Node.js** 20+
- **CMake** 3.14+ ([download](https://cmake.org/download/))
- a **C++17 toolchain** — Visual Studio Build Tools 2017+ (Windows),
  `build-essential` (Linux), `xcode-select --install` (macOS)

See [INSTALLATION.md](INSTALLATION.md) for what runs during install and how to
troubleshoot it.

## Quick start

```javascript
const { RatsNode } = require('librats');

const node = new RatsNode({ listenPort: 8080, dataDir: './state' });

// Everything below happens before start().
node.onPeerConnected((peerId) => {
  console.log(`+ ${peerId}`);
  node.send(peerId, 'chat', 'Hello from Node.js!');
});
node.on('chat', (peerId, data) => {
  console.log(`[chat] ${peerId}: ${data.toString('utf8')}`);
});
node.enableDht();       // find peers on the mainline DHT
node.enableMdns();      // …and on the local network

node.start();
console.log(node.localId, 'listening on', node.listenPort);
```

### Pub/sub

```javascript
node.enablePubsub();
node.subscribe('lobby', (peerId, topic, data) => {
  console.log(`[${topic}] ${peerId}: ${data.toString('utf8')}`);
});
node.start();
node.publish('lobby', 'hi everyone');
```

### Typed JSON messaging

Values are serialized and parsed for you — handlers receive the parsed value.

```javascript
node.enableJson();
node.onJson('greeting', (peerId, value) => console.log(peerId, value.hello));
node.start();
node.broadcastJson('greeting', { hello: 'world' });
```

### File transfer

```javascript
node.enableFileTransfer('./tmp');   // in-progress downloads live here

node.onFileOffer((peerId, transferId, name, size, isDirectory) => {
  node.acceptFile(peerId, transferId, `./downloads/${name}`);
});
node.onFileProgress((transferId, peerId, done, total) => {
  console.log(`${transferId}: ${done}/${total}`);
});
node.onFileComplete((transferId, success, path) => {
  console.log(`${transferId} ${success ? 'done' : 'failed'} ${path}`);
});

node.start();
const transferId = node.sendFile(peerId, './myfile.txt');  // 0 on failure
```

### NAT traversal

Port forwarding is the easy path; hole punching covers the networks where it
fails. Both are opt-in, and punching needs peers that relay the rendezvous.

```javascript
node.enablePortMapping();     // UPnP IGD + NAT-PMP
node.enableHolePunch(true);   // true = also relay other peers' rendezvous
node.start();

node.punchPeer(peerId);       // success arrives as onPeerConnected
console.log(node.natMapping); // NatMapping.ENDPOINT_INDEPENDENT ⇒ punchable
```

## API

### Construction

```javascript
new RatsNode(port)     // listen on port (0 = ephemeral)
new RatsNode(config)   // full config
```

| config field | default | meaning |
|---|---|---|
| `listenPort` | `0` | inbound port shared by both transports; 0 = ephemeral |
| `enableListen` | `true` | `false` makes a dial-only node |
| `bindAddress` | `"::"` | dual-stack wildcard by default |
| `security` | `Security.NOISE` | or `Security.PLAINTEXT` |
| `dataDir` | — | persistent identity + subsystem state; omit for an ephemeral identity |
| `protocol` | `"librats/1.0"` | handshake app id; peers whose protocol differs cannot connect |
| `maxPeers` | `0` | established-peer cap; 0 = unlimited |
| `enableTcp` / `enableUdp` | `true` | which wires to accept and dial on |
| `preferredTransport` | `Transport.UDP` | which one a dial tries first |
| `transportFallbackMs` | `1200` | delay before racing the other; 0 disables |

### Lifecycle

`start()` · `stop()` · `destroy()`

### Properties

`listenPort` · `localId` · `protocol` · `transports` · `peerCount` · `peerIds` ·
`maxPeers` *(settable)* · `natMapping`

### Connections

`connect(host, port)` · `peerTransport(peerId)` · `peerTransports(peerId)`

### Raw channel messaging

`send(peerId, channel, data)` · `broadcast(channel, data)` ·
`on(channel, (peerId, data) => …)` — `data` is a `Buffer` in, `string | Buffer` out

### Peer events *(before start)*

`onPeerConnected(cb)` · `onPeerDisconnected(cb)`

### Subsystems *(enable before start)*

| subsystem | enable | then |
|---|---|---|
| DHT discovery | `enableDht(dhtPort?, discoveryKey?)` | — |
| mDNS discovery | `enableMdns()` | — |
| NAT port mapping | `enablePortMapping(upnp?, natpmp?)` | — |
| Hole punching | `enableHolePunch(serveAsRelay?)` | `punchPeer(peerId)`, `natMapping` |
| Pub/sub | `enablePubsub()` | `subscribe(topic, cb)`, `unsubscribe(topic)`, `publish(topic, data)` |
| Typed JSON | `enableJson()` | `onJson(type, cb)`, `onceJson(type, cb)`, `offJson(type)`, `sendJson(peerId, type, value)`, `broadcastJson(type, value)` |
| File transfer | `enableFileTransfer(tempDir?)` | `onFileOffer/onFileProgress/onFileComplete`, `sendFile`, `sendDirectory`, `acceptFile`, `rejectFile`, `cancelFile`, `pauseFile`, `resumeFile` |
| Liveness | `enablePing()` | `peerRttMs(peerId)` — ms, or -1 if unknown |
| Reconnection | `enableReconnect()` | `addReconnect(host, port)`, `removeReconnect(host, port)` |

### Module level

`version()` · `versionInfo()` · `gitDescribe()` · `abi()` ·
`setLogLevel(level)` · `setLogFile(path?)` ·
`Security` · `Transport` · `TransportMask` · `NatMapping` · `LogLevel`

## TypeScript

Definitions ship with the package.

```typescript
import { RatsNode, Security } from 'librats';

const node = new RatsNode({ listenPort: 8080, security: Security.NOISE });
node.start();
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
npm run verify     # check a fresh install end-to-end
LIBRATS_DEBUG=1 node examples/basic_client.js   # log which addon was loaded
```

## License

MIT — see [LICENSE](../LICENSE).
