<p align="center">
  <a href="https://librats.com"><img src="https://raw.githubusercontent.com/DEgITx/librats/master/docs/logo.png" alt="librats: fast, secure, simple p2p library" width="600"></a>
</p>

# librats for Node.js

[![npm](https://img.shields.io/npm/v/librats.svg)](https://www.npmjs.com/package/librats)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/DEgITx/librats/blob/master/LICENSE)
[![node: >=20](https://img.shields.io/badge/node-%3E%3D20-brightgreen.svg)](https://nodejs.org)

**Peer-to-peer networking for Node.js.** Your programs connect to each other
directly, with no server in between, over encrypted connections. They find
each other on the local network or across the internet, get through home
routers, and exchange messages, JSON values and files.

You could build with it:

- a chat or messenger with no server
- an app whose copies on several computers keep each other in sync
- a tool that finds other copies of itself on the local network
- file sharing, or live audio and video between peers
- a Node service that talks to apps built on librats in other languages: the
  same library exists for C++, C, Python, Java/Android, React Native and iOS

Things to know before you pick it:

- **The networking is native.** Sockets, encryption and delivery run in C++ on
  their own threads, not on the event loop, so one node keeps thousands of peers
  connected and moves gigabits per second.
- **It runs in Node.js, not in the browser.** It is a native addon, so it needs
  Node.js 20+ on Windows, Linux or macOS, and it is compiled when installed.
- **It speaks its own protocol.** It uses the BitTorrent DHT to find peers, but it
  connects only to other librats programs, not to WebRTC, libp2p or BitTorrent
  clients.

## Documentation

- **This page** is the guide: installation, the concepts, and every feature with
  an example.
- **[`index.d.ts`](https://github.com/DEgITx/librats/blob/master/nodejs/lib/index.d.ts)**
  is the full API reference, every method and option with its default. The types
  ship with the package, so your editor shows the same text on hover.
- **[Examples](https://github.com/DEgITx/librats/tree/master/nodejs/examples)**:
  runnable scripts, a chat, pub/sub, file transfer.
- **[librats.com](https://librats.com)** and the
  [main README](https://github.com/DEgITx/librats#readme) describe the library as
  a whole, how it works inside, and the other languages.
- **Questions and bugs:**
  [GitHub issues](https://github.com/DEgITx/librats/issues).

On this page:

- [Installation](#installation)
- [Hello, world](#hello-world) and [a first real node](#a-first-real-node)
- [Example: a chat with no server](#example-a-chat-with-no-server)
- [Connecting to peers](#connecting-to-peers) and [who can connect](#who-can-connect)
- [Sending messages](#sending-messages), including bulk and live audio/video
- [More features](#more-features): JSON, pub/sub, file transfer, NAT traversal, reconnection
- [Configuration](#configuration), [lifecycle](#lifecycle), [errors](#errors),
  [logging](#logging-and-version)

## Installation

```bash
npm install librats
```

There is no prebuilt binary yet: installing compiles the C++ library and the
addon, which takes a few minutes the first time. You need:

- Node.js 20 or newer
- CMake 3.14 or newer
- Python 3, which node-gyp runs on
- a C++17 compiler: Visual Studio Build Tools 2017+ on Windows (the "Desktop
  development with C++" workload), `build-essential` on Linux, Xcode Command
  Line Tools on macOS

If the install fails, it is almost always one of these missing or not on the
`PATH`; [INSTALLATION.md](https://github.com/DEgITx/librats/blob/master/nodejs/INSTALLATION.md)
goes through the build step by step. The [hello world](#hello-world) below is a
quick check that the install worked.

The package is CommonJS and works from ES modules and TypeScript too:

```javascript
const { RatsNode } = require('librats');         // CommonJS
import { RatsNode, setLogLevel } from 'librats'; // ES module or TypeScript
```

## Hello, world

Two nodes in one script, so it runs on one machine with nothing else to set up:

```javascript
const { RatsNode, setLogLevel } = require('librats');

setLogLevel('warn');   // librats logs its startup at 'info'; keep the output short

const alice = new RatsNode();
const bob = new RatsNode();

bob.on('greeting', (peerId, data) => {
  console.log(`bob got "${data}" from ${peerId.slice(0, 8)}…`);
  alice.destroy();     // a node keeps the process running until it is destroyed
  bob.destroy();
});

alice.onPeerConnected((peerId) => {
  console.log(`alice is connected to ${peerId.slice(0, 8)}…`);
  alice.send(peerId, 'greeting', 'hello, bob');
});

alice.start();
bob.start();
alice.connect('127.0.0.1', bob.listenPort);
```

```text
alice is connected to de975867…
bob got "hello, bob" from bafc5b54…
```

What happened: each node got a **peer id**, a long hex string that is its
identity. `start()` opened a port, picked by the system because none was given.
Alice dialed Bob's port; the two exchanged keys, and once each knew who the other
is, `onPeerConnected` fired. Alice then sent a message on a **channel** named
`'greeting'`, and Bob's handler for that channel received it.

In a real app each node is a separate program, usually on its own computer, and
the nodes find each other by themselves instead of being told an address.

## A first real node

```javascript
const { RatsNode } = require('librats');

const node = new RatsNode({ listenPort: 8080, dataDir: './state' });

node.onPeerConnected((peerId) => node.send(peerId, 'chat', 'hello'));
node.on('chat', (peerId, data) => console.log(peerId, data.toString()));
node.enableMdns();   // find other nodes on the local network

node.start();
console.log('I am', node.localId, 'on port', node.listenPort);
```

Run this script on two computers in the same network. The nodes find each other,
connect, and greet each other. To connect by hand instead, call
`node.connect('192.168.1.10', 8080)` after `start()`.

A few things to know from the start:

- **A node is identified by its peer id**, a 64-character hex string. The id is
  the node's public key, so nobody else can claim it. Pass `dataDir` to keep the
  same identity across restarts; without it the node gets a new id every run.
- **`protocol` separates applications.** It defaults to `'librats/1.0'`. It is
  bound into the handshake, so nodes with different protocols cannot connect to
  each other, and the DHT only finds nodes with the same one. Give your app its
  own, such as `'my-app/1.0'`. It is not a password, though: see
  [who can connect](#who-can-connect).
- **Set the node up before `start()`.** Features (`enableMdns()`,
  `enableDht()`, …) and the node's own handlers (`on`, `onPeerConnected`, …)
  can only be added before the node starts; afterwards they throw
  `ALREADY_STARTED`. JSON handlers and pub/sub subscriptions are the exception
  and can come and go at any time.
- **Handlers run on the JS thread.** librats does its networking on its own
  threads and passes events to JavaScript through the event loop, so handlers are
  ordinary JS code. A busy JS thread does not slow the network down; events
  wait in a queue until it is free, and that queue grows meanwhile.
- **Destroy the node when you are done.** While a node has handlers registered,
  it keeps the process alive, so the program does not end until you call
  `destroy()`. See [lifecycle](#lifecycle).

## Example: a chat with no server

Everyone who runs this script with the same room name is in the same chat.
Nodes on one network find each other over mDNS, and nodes elsewhere through the
DHT. `/connect` dials someone directly.

```javascript
const readline = require('readline');
const { RatsNode, setLogLevel } = require('librats');

const [name = 'anon', room = 'lobby', port = '0'] = process.argv.slice(2);
setLogLevel('error');    // library logs would interleave with the chat

// The protocol is bound into the handshake: only nodes in the same room can
// connect, and the DHT, which searches by protocol, looks for exactly them.
const node = new RatsNode({ protocol: `rats-chat/${room}`, listenPort: Number(port) });

node.enableMdns();       // the local network
node.enableDht();        // the internet
node.enableJson();       // messages are { name, text } objects

const short = (peerId) => peerId.slice(0, 8);

node.onPeerConnected((peerId) => print(`* ${short(peerId)} joined`));
node.onPeerDisconnected((peerId, reason) => print(`* ${short(peerId)} left (${reason})`));
node.onJson('say', (peerId, msg) => {
  // Anything can arrive from a peer, so check the shape before using it.
  if (typeof msg?.text !== 'string') return;
  print(`${String(msg.name).slice(0, 32)}: ${msg.text}`);
});

node.start();
console.log(`room "${room}", port ${node.listenPort}, id ${short(node.localId)}`);
console.log('/connect <host> <port>, /peers, /quit\n');

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
rl.setPrompt('> ');
rl.prompt();

rl.on('line', (line) => {
  const [command, ...args] = line.trim().split(/\s+/);
  try {
    if (command === '/connect') node.connect(args[0], Number(args[1]));
    else if (command === '/peers') console.log(node.peerIds.map(short).join(' ') || 'nobody yet');
    else if (command === '/quit') return rl.close();
    else if (line.trim()) node.broadcastJson('say', { name, text: line.trim() });
  } catch (err) {
    console.log(`! ${err.message}`);
  }
  rl.prompt();
});

// Ctrl+C or Ctrl+D. The node's callbacks keep the process alive, so destroy it.
let closed = false;
rl.on('SIGINT', () => rl.close());
rl.on('close', () => {
  closed = true;
  node.destroy();
});

// Print over the prompt line without mangling what is being typed.
function print(text) {
  if (closed) return;   // a last event can arrive while the node is being destroyed
  readline.clearLine(process.stdout, 0);
  readline.cursorTo(process.stdout, 0);
  console.log(text);
  rl.prompt(true);
}
```

To try it, save it as `chat.js` in a project where librats is installed, and
run it in two terminals, on one computer or on two in the same network:

```bash
node chat.js alice
node chat.js bob
```

```text
room "lobby", port 50113, id 850568e0       room "lobby", port 64991, id f7e5a523
/connect <host> <port>, /peers, /quit       /connect <host> <port>, /peers, /quit

* f7e5a523 joined                           * 850568e0 joined
> bob: hello from bob                       > hello from bob
> привет 👋                                 alice: привет 👋
```

What happens and where the limits are:

- **On the same network the nodes find each other by themselves**, over mDNS,
  usually within a few seconds. Where multicast does not get through (some
  guest Wi-Fi, VPNs), `/connect <host> <port>` dials directly; the port is the
  one the script prints at start.
- **Through the internet, the DHT needs time and a reachable node.** A new node
  first joins the DHT, then announces itself and searches every 30 seconds, so
  finding each other takes from tens of seconds to a few minutes. Then one side
  has to accept the connection: a public address, a forwarded port, or a router
  that agrees to forward one (`node.enablePortMapping()` asks it over UPnP and
  NAT-PMP). Two nodes behind NAT with nobody in common to help them cannot
  connect, as described in [NAT traversal](#nat-traversal).
- **There is no history.** A message reaches whoever is connected at the moment.
  `broadcastJson` sends it to every connected peer and the peers do not pass it
  on, so a large room needs every member connected to every other.
  [`examples/gossipsub_chat.js`](https://github.com/DEgITx/librats/blob/master/nodejs/examples/gossipsub_chat.js) is the same chat over
  pub/sub, where messages also spread through intermediate peers.

## Connecting to peers

```javascript
node.connect('example.com', 8080);   // a name or an IP address
node.disconnect(peerId);             // false if it was not connected

node.peerCount;                      // how many peers are connected
node.peerIds;                        // their ids
node.peerInfo(peerId);               // { transport, direction, address, transports }, or null
node.maxPeers = 50;                  // cap on peers, enforced on inbound; 0 is no cap
```

`connect()` returns immediately. A connection that succeeds arrives as
`onPeerConnected`. One that fails arrives as `onDialFailed`, but only for an IP
address: a dial by host name fails silently. `onPeerDisconnected` reports why a
peer left as a string: `'peer-closed'`, `'idle-timeout'`, `'slow-consumer'`, and
so on (see `CloseReason` in `index.d.ts`).

Each node listens on one port over both UDP and TCP. A dial tries UDP first and
also tries TCP if UDP does not succeed within 1.2 seconds. `peerInfo(id).transport`
shows which one was used.

What the node knows about itself: `node.localId`, `node.listenPort` (the real
port when 0 was asked for), `node.observedAddresses` (its own addresses as
connected peers see them, which is how a node behind NAT learns its public
address) and `node.natMapping` (see [NAT traversal](#nat-traversal)).

There are three ways for nodes to find each other without knowing an address,
and they can be combined:

| | How it finds peers |
|---|---|
| `enableMdns()` | multicast on the local network |
| `enableDht(port?, discoveryKey?)` | the BitTorrent mainline DHT, worldwide. By default it looks for nodes with the same `protocol`; `dhtSetKeys([...])` replaces the keys at any time, also while running |
| `enablePeerExchange()` | connected peers tell each other about the peers they hold, so one contact is enough to find the rest |

### Who can connect

Every connection is encrypted and authenticated with the Noise protocol. When
`onPeerConnected` reports a peer id, the other side has proved it holds that
id's private key, and nobody in between can read or change the traffic.

What librats does not decide is whether you want that peer. Any node with the
same `protocol` string can connect to yours, and the string is not secret: it is
in your app, and the DHT lookup is derived from it. If only certain peers may
talk to your node, keep a list of the ids you trust, which stay fixed when the
peers use `dataDir`, and drop everyone else:

```javascript
const trusted = new Set(['3f2a…', '9c41…']);   // full 64-character ids
node.onPeerConnected((peerId) => {
  if (!trusted.has(peerId)) node.disconnect(peerId);
});
```

The same goes for what peers send: a handler gets whatever bytes the peer chose
to send, so check them before using them.

## Sending messages

Messages travel on named **channels**: a name you choose, such as `'chat'` or
`'state'`. You send a string or a Buffer, and the handler always gets a Buffer.

```javascript
node.on('state', (peerId, data) => apply(JSON.parse(data)));

node.send(peerId, 'state', JSON.stringify(state));   // one peer; throws NO_SUCH_PEER if not connected
node.broadcast('state', JSON.stringify(state));      // every connected peer
```

What a channel guarantees:

- **Reliable and in order.** Everything a node sends to a peer arrives in the
  order it was sent, across all channels ([live messages](#live-messages-audio-and-video)
  aside).
- **Only while the connection lasts.** If the peer disconnects, what was still
  queued for it is lost. There is no store-and-forward: a peer that is offline
  does not get the message later.
- **Up to almost 64 MiB per message.** A larger message is not delivered:
  `send()` still returns, and a warning in the log says it was refused. Split
  big data into pieces, or use [file transfer](#file-transfer).
- **Only to a peer that listens.** A message on a channel the receiver has no
  handler for is dropped silently.

Channel names are hashed to 16-bit ids on the wire. Two different names can in
principle get the same id; if two of the names your node listens on do, a
warning is logged when the second handler is registered.

### When you send a lot

`send()` returns once the message is in the queue, before it reaches the peer. If
you put messages in faster than the connection carries them, the queue grows,
and past its limit (8 MiB by default, `sendQueueLimit`) the peer is disconnected
with reason `'slow-consumer'`. To avoid that, check `peerWritable(peerId)` after
each send, and once it returns false, wait for `onPeerWritable`:

```javascript
function pump(peerId) {
  while (chunks.length) {
    node.send(peerId, 'bulk', chunks.shift());
    if (!node.peerWritable(peerId)) return;   // continue when onPeerWritable fires
  }
}
node.onPeerWritable(pump);
```

For files, use [file transfer](#file-transfer) instead, which already does this.

### Live messages: audio and video

The fourth argument of `send` and `broadcast` is a lifetime in milliseconds. A
message with a lifetime is **live**: it arrives within that time or not at all,
never partly and never twice, and it is not ordered with other messages. An old
video frame is useless, and this keeps a stale one from delaying the next.

```javascript
node.send(peerId, 'video', frame, 150);   // delivered within 150 ms or dropped
```

The longest lifetime is `LIVE_MAX_LIFETIME_MS` (30 s) and the largest payload is
`LIVE_MAX_PAYLOAD` (4 MiB). The receiver needs nothing special. An encoder can
adapt its bitrate to `pathStats(peerId)`, which reports the bandwidth estimate,
round trip, loss, queued bytes and how many live messages expired. The
`onPeerPath` handler receives the same figures every 100 ms.

## More features

Each of these is off until enabled, and is enabled before `start()`:

| Feature | Enable | Then use |
|---|---|---|
| DHT discovery | `enableDht(port?, discoveryKey?)` | `dhtSetKeys([...])` |
| mDNS discovery | `enableMdns()` | |
| Peer exchange | `enablePeerExchange()` | |
| JSON messages | `enableJson()` | `onJson`, `onceJson`, `offJson`, `sendJson`, `broadcastJson` |
| Pub/sub (GossipSub) | `enablePubsub()` | `subscribe`, `unsubscribe`, `publish` |
| File transfer | `enableFileTransfer(tempDir?)` | `onFileOffer`, `onFileProgress`, `onFileComplete`, `sendFile`, `sendDirectory`, `acceptFile`, `rejectFile`, `pauseFile`, `resumeFile`, `cancelFile` |
| Port mapping | `enablePortMapping(upnp?, natpmp?)` | |
| Hole punching | `enableHolePunch(serveRendezvous?)` | `punchPeer(id)`, `natMapping` |
| Relaying | `enableRelay(serve?)` | `connectViaRelay(id)` |
| Ping | `enablePing()` | `peerRttMs(id)` |
| Reconnection | `enableReconnect()` or `enableReconnectLost(lostForMs)` | `addReconnect(host, port)`, `removeReconnect(host, port)` |

### JSON messages and pub/sub

JSON messages are channels that carry values instead of bytes. `sendJson` calls
`JSON.stringify`, and the handler receives the parsed value. Values come from
other machines, so check their shape before trusting them.

Pub/sub works by topic instead of by peer. A published message reaches every
node subscribed to the topic, including through peers in between, so it scales
to groups where not everybody is connected to everybody.

```javascript
node.enableJson();
node.onJson('greeting', (peerId, value) => console.log(value.hello));

node.enablePubsub();
node.subscribe('news', (peerId, topic, data) => console.log(topic, data.toString()));

node.start();
node.broadcastJson('greeting', { hello: 'world' });
node.publish('news', 'something happened');
```

Each topic has one handler; subscribing again replaces it.

### File transfer

The sender offers a file or a directory. The receiver accepts it, choosing where
to save it, or rejects it. Both sides name a transfer by `(peerId, transferId)`.

```javascript
const path = require('path');

node.enableFileTransfer('./tmp');   // where partial downloads are kept
node.onFileOffer((peerId, transferId, name, size, isDirectory) => {
  // `name` comes from the sender; basename() keeps a name like '../../x' in downloads/
  node.acceptFile(peerId, transferId, path.join('./downloads', path.basename(name)));
});
node.onFileProgress((p) => console.log(p.transferId, p.status, `${p.bytesTransferred}/${p.totalBytes}`));
node.onFileComplete((peerId, transferId, success, path) => console.log(transferId, success, path));
node.start();

const transferId = node.sendFile(peerId, './video.mp4');   // throws NO_SUCH_PEER / NOT_FOUND
```

The name in an offer is whatever the sender put there, so never use it as a
path unchecked. librats does check the paths inside an offered directory and
rejects the offer if one of them leads outside it. The three file handlers hold
one handler each; registering again replaces it.

### NAT traversal

Most nodes sit behind a router that does not accept incoming connections, and two
such nodes cannot simply dial each other. librats has three remedies, from the
cheapest to the most expensive:

1. **Port mapping** asks the router to forward the port, over UPnP or NAT-PMP.
   Many home routers agree; corporate and mobile networks usually do not.
2. **Hole punching**: a peer both sides are already connected to arranges for
   them to dial each other at the same moment, which opens both NATs. Every node
   involved needs `enableHolePunch()`. It cannot work behind a symmetric NAT,
   which `node.natMapping === 'endpoint-dependent'` reports.
3. **Relaying** carries the connection through a peer both sides share. It stays
   encrypted end to end, so the relay cannot read it, and
   `peerInfo(id).transport` reports `'relay'`. Only nodes started with
   `enableRelay(true)` carry other peers' traffic, because it costs them
   bandwidth.

```javascript
node.enablePortMapping();
node.enableHolePunch();
node.enableRelay();
node.start();

node.punchPeer(peerId);   // false if there is nothing to do or nobody to help
```

With hole punching and relaying both enabled, a punch that cannot work falls
back to a relay by itself, and a relayed peer moves to a direct connection when
a later punch succeeds.

### Reconnection

`enableReconnect()` redials peers that dropped, with growing pauses between
attempts. With `dataDir` the list survives a restart. `addReconnect(host, port)`
adds an address to keep connected, and can be called while the node is running.

`enableReconnectLost(lostForMs)` does the same and also covers a peer that was
**lost** rather than one that **left**: a peer whose connection closed with
neither side closing it, because it went silent or stopped answering. Such a
peer is redialed where it was last seen for up to `lostForMs`. Use one of the
two, not both.

## Configuration

Everything is optional:

```javascript
new RatsNode({
  protocol: 'my-app/1.0',     // default 'librats/1.0'
  dataDir: './state',         // identity, DHT table, reconnect list; default none
  listenPort: 8080,           // default 0, any free port
  maxPeers: 100,              // default 0, no cap
});
```

| Option | Default | What it does |
|---|---|---|
| `protocol` | `'librats/1.0'` | app id bound into the handshake |
| `dataDir` | none | where the identity, DHT routing table and reconnect list are kept |
| `security` | `'noise'` | `'plaintext'` turns encryption off, for debugging only |
| `listenPort` | `0` | shared by UDP and TCP; 0 picks a free one |
| `bindAddress` | `'::'` | every interface, IPv4 and IPv6 |
| `dialOnly` | `false` | no listener, outgoing connections only |
| `maxPeers` | `0` | cap on connected peers, enforced on incoming ones; 0 is no cap |
| `transports` | `['udp', 'tcp']` | which transports to run |
| `preferredTransport` | `'udp'` | which one a dial tries first |
| `transportFallbackMs` | `1200` | how long the first transport tries alone before the other joins; `Infinity` is never |
| `sendQueueLimit` | 8 MiB | queue size past which a peer is dropped as `'slow-consumer'` |
| `pathSampleMs` | `0` | how often `pathStats` is refreshed; 0 is only while an `onPeerPath` handler exists |
| `congestionControl` | `'bbr'` | or `'reno'`, for UDP connections |
| `udpReceiveWindow` | 16 MiB | flow-control window of one UDP connection |
| `udpReceiveBudget` | 64 MiB | out-of-order bytes all UDP connections may hold together |
| `udpOffload` | `true` | kernel segmentation offload for UDP, where available |
| `udpIdleTimeoutMs` | 45000 | silence after which a UDP peer counts as lost (`'idle-timeout'`) |
| `reactorThreads` | `1` | networking threads |
| `networkMonitor` | `true` | react when interfaces or addresses change |

A combination no node can run with, such as `preferredTransport: 'tcp'` with
`transports: ['udp']`, makes the constructor throw `INVALID_CONFIG`. A negative
or fractional number throws a `RangeError`.

## Lifecycle

```javascript
const node = new RatsNode(config);   // nothing runs yet
node.start();                        // sockets open, features start
node.stop();                         // every connection closes; start() works again
node.destroy();                      // stopped and freed; any later call throws DESTROYED
```

- **`destroy()` is what lets the process exit.** As long as a node has handlers
  registered, Node.js keeps running for it, the same way an open server does.
- **A node can be destroyed from inside its own handler.** Handlers run on the
  JS thread, not on librats' threads, so this is safe.
- **A node in a worker thread** is torn down with the worker, even without
  `destroy()`.
- **A restarted node keeps its id and features**, but not its connections:
  dial again, or let discovery and [reconnection](#reconnection) do it.

## Errors

A failed call throws an `Error` whose `code` names the cause:

```javascript
try {
  node.send(peerId, 'chat', 'hi');
} catch (err) {
  if (err.code === 'NO_SUCH_PEER') { /* the peer left in the meantime */ }
}
```

| `code` | Meaning |
|---|---|
| `ALREADY_STARTED` | this has to happen before `start()` |
| `NOT_STARTED` | this has to happen after `start()` |
| `NOT_ENABLED` | the feature was not enabled |
| `NO_SUCH_PEER` | the peer is not connected |
| `NOT_FOUND` | no such file or transfer |
| `BIND` | the port is taken |
| `INVALID_ARG` | a bad argument, such as a live message over 4 MiB |
| `INVALID_CONFIG` | the constructor's configuration cannot work |
| `DESTROYED` | the node was destroyed |
| `DECLINED`, `INTERNAL` | refused, or failed inside the library |

An argument of the wrong type throws a `TypeError` or a `RangeError`. Calls for
which "nothing to do" is a normal answer do not throw; they return `false`
(`disconnect`, `punchPeer`, `connectViaRelay`, `pauseFile`, …) or `null`
(`peerInfo`, `pathStats`, `peerRttMs`).

## Logging and version

```javascript
const { setLogLevel, setLogFile, version } = require('librats');

setLogLevel('warn');            // 'debug' | 'info' (default) | 'warn' | 'error'
setLogFile('./librats.log');    // also write to a file; setLogFile() stops it
console.log(version().string);  // e.g. '3.0.4.944'
```

Logs go to the console: errors to stderr, everything else to stdout. These
settings apply to the whole library, every node in the process.

## Examples

| | |
|---|---|
| [`chat.js`](https://github.com/DEgITx/librats/blob/master/nodejs/examples/chat.js) | the chat above |
| [`gossipsub_chat.js`](https://github.com/DEgITx/librats/blob/master/nodejs/examples/gossipsub_chat.js) | the same chat over pub/sub |
| [`basic_client.js`](https://github.com/DEgITx/librats/blob/master/nodejs/examples/basic_client.js) | channels, JSON and peer events |
| [`file_transfer.js`](https://github.com/DEgITx/librats/blob/master/nodejs/examples/file_transfer.js) | sending and receiving files |

The examples are in the repository, not in the npm package. Each one says how
to run it at the top. To use one in your own project, copy it and change
`require('../lib/index')` to `require('librats')`. To run them where they are,
from a clone:

```bash
git clone https://github.com/DEgITx/librats.git
cd librats/nodejs
npm install
node examples/basic_client.js 8080                    # one terminal
node examples/basic_client.js 8081 127.0.0.1 8080     # another
```

## Working on the bindings

In a clone, `npm install` builds everything and `npm test` runs the tests.
[INSTALLATION.md](https://github.com/DEgITx/librats/blob/master/nodejs/INSTALLATION.md)
explains how the build is put together.

## License

MIT, see [LICENSE](https://github.com/DEgITx/librats/blob/master/LICENSE).
