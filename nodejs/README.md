# LibRats Node.js Bindings

Node.js bindings for librats — a high-performance peer-to-peer networking library with secure transport, DHT/mDNS discovery, pub/sub, typed JSON messaging and file transfer.

## Features

- **Peer-to-peer networking** — direct, authenticated connections between peers
- **Secure transport** — Noise XX encryption + authentication by default (or plaintext)
- **DHT discovery** — decentralized peer discovery
- **mDNS discovery** — local-network peer discovery
- **NAT port mapping** — automatic UPnP / NAT-PMP port forwarding
- **Raw channel messaging** — named channels carrying arbitrary bytes
- **Pub/Sub (GossipSub)** — topic-based publish/subscribe
- **Typed JSON messaging** — route JSON payloads by message type
- **File transfer** — send/receive files and directories (push model)
- **Liveness** — per-peer RTT probing
- **Automatic reconnection** — re-dial dropped peers with backoff

## Design: opt-in subsystems

Subsystems are explicit. Discovery, pub/sub, typed JSON, file transfer, ping and
reconnect must each be turned on with the matching `enable*()` **before**
`start()`. Callbacks must also be registered before `start()`. Native calls
**throw** an `Error` (message `librats: <CODE>`) on a non-OK result.

## Installation

```bash
npm install librats
```

The install builds the native librats library with CMake, then compiles the
Node.js addon against it.

### Prerequisites

- **Node.js** 20.0.0 or higher
- **CMake** 3.14 or higher ([download](https://cmake.org/download/))
- **C++ toolchain**:
  - Windows: Visual Studio Build Tools 2017+
  - Linux: `sudo apt install build-essential cmake`
  - macOS: `xcode-select --install`

## Quick Start

### Basic messaging

```javascript
const { RatsClient, Security } = require('librats');

// Listen on port 8080 (Noise transport is the default).
const client = new RatsClient({ listenPort: 8080, security: Security.NOISE });

// Register callbacks BEFORE start().
client.onPeerConnected((peerId) => {
  console.log(`Peer connected: ${peerId}`);
  client.send(peerId, 'chat', 'Hello from Node.js!');
});

client.on('chat', (peerId, data) => {
  console.log(`[chat] ${peerId}: ${data.toString('utf8')}`);
});

client.start();
client.connect('127.0.0.1', 8081);
```

### File transfer

```javascript
const { RatsClient } = require('librats');

const client = new RatsClient(8080);

// Enable the subsystem and register callbacks BEFORE start().
client.enableFileTransfer('./tmp');

client.onFileOffer((peerId, transferId, name, size, isDirectory) => {
  console.log(`Offer "${name}" (${size} bytes) from ${peerId}`);
  client.acceptFile(peerId, transferId, `./downloads/${name}`);
});

client.onFileProgress((transferId, peerId, sent, total, status) => {
  console.log(`Transfer ${transferId}: ${sent}/${total}`);
});

client.onFileComplete((transferId, success, path) => {
  console.log(`Transfer ${transferId} ${success ? 'done' : 'failed'}: ${path}`);
});

client.start();

// Returns a numeric transfer id (0 on failure).
const transferId = client.sendFile('peer_id_here', './myfile.txt');
```

### Pub/Sub chat

```javascript
const { RatsClient } = require('librats');

const client = new RatsClient(8080);

// Enable pub/sub and subscribe BEFORE start().
client.enablePubsub();
client.subscribe('general-chat', (peerId, topic, data) => {
  console.log(`[${topic}] ${peerId}: ${data.toString('utf8')}`);
});

client.start();
client.publish('general-chat', JSON.stringify({ username: 'Alice', message: 'Hi!' }));
```

### Typed JSON messaging

```javascript
const { RatsClient } = require('librats');

const client = new RatsClient(8080);
client.enableJson();
client.onJson('greeting', (peerId, json) => {
  console.log(`greeting from ${peerId}:`, JSON.parse(json));
});
client.start();

// json must be valid JSON text.
client.broadcastJson('greeting', JSON.stringify({ hello: 'world' }));
```

## API Reference

### Construction

- `new RatsClient(port)` — listen on `port` (0 = ephemeral), Noise transport.
- `new RatsClient(config)` — full config object:
  - `listenPort?: number` (0 = ephemeral)
  - `enableListen?: boolean` (false = dial-only)
  - `bindAddress?: string` (default `"::"`)
  - `security?: Security` (`Security.NOISE` | `Security.PLAINTEXT`)
  - `dataDir?: string` (persistent identity + subsystem state; empty = ephemeral)
  - `protocol?: string` (handshake app id, e.g. `"myapp/1.0"`; default `"librats/1.0"`)
  - `maxPeers?: number` (0 = unlimited)

### Lifecycle / core

- `start(): void` — throws on bind failure or if already started
- `stop(): void`
- `getListenPort(): number`
- `getOurPeerId(): string | null` — 64-char hex
- `getProtocol(): string | null` — handshake app id (e.g. `"librats/1.0"`)

### Connections

- `connect(host, port): void`
- `getPeerCount(): number`
- `getPeerIds(): string[]`
- `setMaxPeers(maxPeers): void` / `getMaxPeers(): number`

### Raw channel messaging

- `send(peerId, channel, data): void` — `data` is `string | Buffer`
- `broadcast(channel, data): void`
- `on(channel, (peerId, data: Buffer) => void): void` *(before start)*

### Peer events *(before start)*

- `onPeerConnected((peerId) => void): void`
- `onPeerDisconnected((peerId) => void): void`

### Discovery / NAT *(enable before start)*

- `enableDht(dhtPort?, discoveryKey?): void`
- `enableMdns(): void`
- `enablePortMapping(enableUpnp?, enableNatpmp?): void`

### Pub/Sub *(enable before start)*

- `enablePubsub(): void`
- `subscribe(topic, (peerId, topic, data: Buffer) => void): void` *(before start)*
- `unsubscribe(topic): void`
- `publish(topic, data): void`

### Typed JSON *(enable before start)*

- `enableJson(): void`
- `onJson(type, (peerId, json) => void): void`
- `onceJson(type, (peerId, json) => void): void`
- `offJson(type): void`
- `sendJson(peerId, type, json): void`
- `broadcastJson(type, json): void`

### File transfer *(enable + register callbacks before start)*

- `enableFileTransfer(tempDir?): void`
- `onFileOffer((peerId, transferId, name, size, isDirectory) => void): void`
- `onFileProgress((transferId, peerId, bytesTransferred, totalBytes, status) => void): void`
- `onFileComplete((transferId, success, path) => void): void`
- `sendFile(peerId, filePath): number` — transfer id (0 on failure)
- `sendDirectory(peerId, dirPath): number`
- `acceptFile(peerId, transferId, destPath): void`
- `rejectFile(peerId, transferId): void`
- `cancelFile / pauseFile / resumeFile (peerId, transferId): void`

### Liveness / reconnect *(enable before start)*

- `enablePing(): void`
- `getPeerRttMs(peerId): number` — ms, or -1 if unknown
- `enableReconnect(): void`
- `addReconnect(host, port): void` / `removeReconnect(host, port): void`

### Module-level

- `getVersionString(): string`
- `getVersion(): { major, minor, patch, build }`
- `getGitDescribe(): string`
- `getAbi(): number`
- `setLogLevel(level: LogLevel): void`
- `setLogFile(path?): void` — omit/empty to disable file logging
- `Security` — `{ NOISE, PLAINTEXT }`
- `LogLevel` — `{ DEBUG, INFO, WARN, ERROR }`
- `constants` — native `SECURITY` / `LOG_LEVELS` / `ERRORS` tables

## Examples

The `examples/` directory contains:

- **`basic_client.js`** — peer events + raw-channel and typed-JSON messaging
- **`file_transfer.js`** — file/directory transfer with interactive CLI
- **`gossipsub_chat.js`** — topic-based chat over pub/sub

```bash
node examples/basic_client.js 8080
node examples/basic_client.js 8081 127.0.0.1 8080
node examples/file_transfer.js 8080
node examples/gossipsub_chat.js 8080 Alice lobby
```

## Testing

```bash
npm test
```

## TypeScript

Full TypeScript definitions are included:

```typescript
import { RatsClient, Security, LogLevel } from 'librats';

const client = new RatsClient({ listenPort: 8080, security: Security.NOISE });
client.start();
```

## Migrating from the old binding

The C ABI was rewritten. Notable changes:

- `onConnection` / `onDisconnect` → `onPeerConnected` / `onPeerDisconnected`.
- `sendString` / `sendBinary` (untyped) → `send(peerId, channel, data)` on a
  **named channel**; receive with `on(channel, cb)`. `broadcastString` /
  `broadcastBinary` → `broadcast(channel, data)`.
- `sendJson(peerId, json)` (untyped) → `sendJson(peerId, type, json)` routed by
  message **type**; `enableJson()` first, receive with `onJson(type, cb)`.
- `subscribeToTopic` / `publishToTopic` → `enablePubsub()` then
  `subscribe(topic, cb)` / `publish(topic, data)`.
- File transfer ids are now **numbers**. `onFileRequest` → `onFileOffer`;
  `acceptFileTransfer(transferId, path)` → `acceptFile(peerId, transferId, path)`;
  added `onFileComplete`. Control calls take `(peerId, transferId)`.
- `startDhtDiscovery(port)` / `startMdnsDiscovery()` → `enableDht(port, key)` /
  `enableMdns()` (call before `start()`).
- New: `enablePing()` + `getPeerRttMs()`, `enableReconnect()` +
  `addReconnect()`, `enablePortMapping()`.
- Operations now **throw** on error instead of returning booleans.

### Removed features

These were dropped with the C ABI rewrite and are no longer available:

- ICE / STUN / TURN (`addStunServer`, `addTurnServer`, `gatherIceCandidates`, …)
- Encryption toggles / key introspection (`setEncryptionEnabled`,
  `getNoiseStaticPublicKey`, …) — security is fixed at construction via
  `config.security`.
- Configuration load/save (`loadConfiguration`, `saveConfiguration`,
  `setDataDirectory`) — replaced by `config.dataDir`.
- Granular logging controls (console toggle, colors, timestamps, rotation) —
  replaced by `setLogLevel` / `setLogFile`.
- Statistics JSON (`getConnectionStatistics`, `getGossipsubStatistics`,
  `getFileTransferStatistics`), historical peers, and discovery on/off toggles.

## Platform Support

- **Windows** — Visual Studio Build Tools
- **Linux** — build-essential
- **macOS** — Xcode Command Line Tools

## Debug logging

```bash
LIBRATS_DEBUG=1 node examples/basic_client.js
```

## License

MIT — see the LICENSE file.

## Support

- [GitHub Issues](https://github.com/librats/librats/issues)
- [Main project README](../README.md)
