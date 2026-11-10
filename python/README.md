<p align="center">
  <a href="https://librats.com"><img src="https://raw.githubusercontent.com/librats/librats/master/docs/logo.png" alt="librats: fast, secure, simple p2p library" width="600"></a>
</p>

# librats for Python

[![PyPI](https://img.shields.io/pypi/v/librats.svg)](https://pypi.org/project/librats/)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/librats/librats/blob/master/LICENSE)
[![python: >=3.8](https://img.shields.io/badge/python-%3E%3D3.8-brightgreen.svg)](https://www.python.org)

**Peer-to-peer networking for Python.** Your programs connect to each other
directly, with no server in between, over encrypted connections. They find
each other on the local network or across the internet, get through home
routers, and exchange messages, JSON values and files.

You could build with it:

- a chat or messenger with no server
- an app whose copies on several computers keep each other in sync
- a tool that finds other copies of itself on the local network
- file sharing between machines
- a Python service that talks to apps built on librats in other languages: the
  same library exists for C++, C, Node.js, Java/Android, React Native and iOS

Things to know before you pick it:

- **The networking is native.** Sockets, encryption and delivery run in the
  C++ library on its own threads. Python only sees the events: a message
  arrived, a peer connected. There is nothing to compile, the library ships
  inside the package.
- **It speaks its own protocol.** It uses the BitTorrent DHT to find peers, but it
  connects only to other librats programs, not to WebRTC, libp2p or BitTorrent
  clients.

## Documentation

- **This page** is the guide: installation, the concepts, and every feature with
  an example.
- **The docstrings** are the full API reference, every method and option with
  its default: `help(librats_py.RatsNode)`, or hover in your editor.
- **[Examples](https://github.com/librats/librats/tree/master/python/librats_py/examples)**:
  a chat, pub/sub, file transfer. They are installed with the package.
- **[librats.com](https://librats.com)** and the
  [main README](https://github.com/librats/librats#readme) describe the library as
  a whole, how it works inside, and the other languages.
- **Questions and bugs:**
  [GitHub issues](https://github.com/librats/librats/issues).

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
pip install librats
```

The package is called `librats`, the module you import is `librats_py`:

```python
from librats_py import RatsNode
```

It needs Python 3.8 or newer. The package ships the compiled library for:

- Windows x64
- Linux x86_64 and aarch64 with glibc 2.28 or newer (Debian 10, Ubuntu 20.04,
  RHEL 8 and later)
- macOS 11 or newer, Intel and Apple Silicon

Nothing else is needed. On any other platform pip finds no matching package;
see [building from source](#building-from-source). The [hello world](#hello-world)
below is a quick check that the install worked.

## Hello, world

Two nodes in one script, so it runs on one machine with nothing else to set up:

```python
import threading
from librats_py import RatsNode, LogLevel, set_log_level

set_log_level(LogLevel.WARN)   # librats logs its startup at INFO; keep the output short

alice = RatsNode()
bob = RatsNode()
done = threading.Event()

def on_greeting(peer_id, data):
    print(f'bob got "{data.decode()}" from {peer_id[:8]}…')
    done.set()

def on_connected(peer_id):
    print(f"alice is connected to {peer_id[:8]}…")
    alice.send(peer_id, "greeting", b"hello, bob")

bob.on("greeting", on_greeting)
alice.on_peer_connected(on_connected)

alice.start()
bob.start()
alice.connect("127.0.0.1", bob.listen_port)

done.wait(10)      # handlers run on librats' own thread; wait here for them
alice.destroy()
bob.destroy()
```

```text
alice is connected to b3eac42c…
bob got "hello, bob" from 58dd7707…
```

What happened: each node got a **peer id**, a long hex string that is its
identity. `start()` opened a port, picked by the system because none was given.
Alice dialed Bob's port; the two exchanged keys, and once each knew who the other
is, `on_peer_connected` fired. Alice then sent a message on a **channel** named
`"greeting"`, and Bob's handler for that channel received it.

The handlers ran on a thread of librats, not on the main thread, which is why
the script waits on an `Event` before it destroys the nodes.

In a real app each node is a separate program, usually on its own computer, and
the nodes find each other by themselves instead of being told an address.

## A first real node

```python
from librats_py import RatsNode

node = RatsNode(8080, data_dir="./state")

node.on_peer_connected(lambda peer_id: node.send(peer_id, "chat", b"hello"))
node.on("chat", lambda peer_id, data: print(peer_id[:8], data.decode()))
node.enable_mdns()   # find other nodes on the local network

with node:           # destroys the node when the block ends
    node.start()
    print("I am", node.local_id, "on port", node.listen_port)
    input("Enter to quit\n")
```

Run this script on two computers in the same network. The nodes find each other,
connect, and greet each other. To connect by hand instead, call
`node.connect("192.168.1.10", 8080)` after `start()`.

A few things to know from the start:

- **A node is identified by its peer id**, a 64-character hex string. The id is
  the node's public key, so nobody else can claim it. Pass `data_dir` to keep the
  same identity across restarts; without it the node gets a new id every run.
- **`protocol` separates applications.** It defaults to `"librats/1.0"`. It is
  bound into the handshake, so nodes with different protocols cannot connect to
  each other, and the DHT only finds nodes with the same one. Give your app its
  own, such as `RatsNode(protocol="my-app/1.0")`. It is not a password, though:
  see [who can connect](#who-can-connect).
- **Set the node up before `start()`.** Features (`enable_mdns()`,
  `enable_dht()`, …) and the node's own handlers (`on`, `on_peer_connected`,
  the file handlers, …) can only be added before the node starts; afterwards
  they raise `RatsAlreadyStartedError`. JSON handlers and pub/sub subscriptions
  are the exception and can come and go at any time.
- **Handlers run on librats' thread.** That thread also does the networking, so
  while a handler runs, the node's traffic waits. Keep handlers short; for slow
  work, put the message on a `queue.Queue` and handle it on a thread of your
  own. An exception raised in a handler is printed to stderr and goes no further.
- **The program has to keep running.** The node works only while the program
  does: when the main thread ends, the nodes are closed. Wait on something:
  `input()`, a loop, or an `Event` as in the hello world.

## Example: a chat with no server

Everyone who runs this script with the same room name is in the same chat.
Nodes on one network find each other over mDNS, and nodes elsewhere through the
DHT. `/connect` dials someone directly.

```python
import sys
from librats_py import RatsNode, RatsError, LogLevel, set_log_level

name = sys.argv[1] if len(sys.argv) > 1 else "anon"
room = sys.argv[2] if len(sys.argv) > 2 else "lobby"
port = int(sys.argv[3]) if len(sys.argv) > 3 else 0
set_log_level(LogLevel.ERROR)   # library logs would interleave with the chat

# The protocol is bound into the handshake: only nodes in the same room can
# connect, and the DHT, which searches by protocol, looks for exactly them.
node = RatsNode(port, protocol=f"rats-chat/{room}")
node.enable_mdns()   # the local network
node.enable_dht()    # the internet
node.enable_json()   # messages are {"name": ..., "text": ...} objects

def short(peer_id):
    return peer_id[:8]

def on_say(peer_id, msg):
    # Anything can arrive from a peer, so check the shape before using it.
    if not isinstance(msg, dict) or not isinstance(msg.get("text"), str):
        return
    print(f"{str(msg.get('name'))[:32]}: {msg['text']}", flush=True)

node.on_peer_connected(lambda peer_id: print(f"* {short(peer_id)} joined", flush=True))
node.on_peer_disconnected(
    lambda peer_id, reason: print(f"* {short(peer_id)} left ({reason.name.lower()})", flush=True))
node.on_json("say", on_say)

with node:   # destroys the node on the way out
    node.start()
    print(f'room "{room}", port {node.listen_port}, id {short(node.local_id)}')
    print("/connect <host> <port>, /peers, /quit\n", flush=True)
    try:
        for line in sys.stdin:   # ends on Ctrl+D (Ctrl+Z, Enter on Windows)
            command, *args = line.split() or [""]
            try:
                if command == "/connect":
                    node.connect(args[0], int(args[1]))
                elif command == "/peers":
                    print(" ".join(map(short, node.peer_ids)) or "nobody yet")
                elif command == "/quit":
                    break
                elif line.strip():
                    node.broadcast_json("say", {"name": name, "text": line.strip()})
            except (RatsError, ValueError, IndexError) as e:
                print(f"! {e}")
    except KeyboardInterrupt:   # Ctrl+C
        pass
```

The script is installed with the package, so you can run it right away, in two
terminals, on one computer or on two in the same network:

```bash
python -m librats_py.examples.chat alice
python -m librats_py.examples.chat bob
```

```text
room "lobby", port 47011, id c875ccab       room "lobby", port 56796, id 04655af7
/connect <host> <port>, /peers, /quit       /connect <host> <port>, /peers, /quit

* 04655af7 joined                           * c875ccab joined
bob: hello from bob                         hello from bob
привет 👋                                   alice: привет 👋
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
  that agrees to forward one (`node.enable_port_mapping()` asks it over UPnP and
  NAT-PMP). Two nodes behind NAT with nobody in common to help them cannot
  connect, as described in [NAT traversal](#nat-traversal).
- **There is no history.** A message reaches whoever is connected at the moment.
  `broadcast_json` sends it to every connected peer and the peers do not pass it
  on, so a large room needs every member connected to every other.
  [`gossipsub_chat.py`](https://github.com/librats/librats/blob/master/python/librats_py/examples/gossipsub_chat.py)
  is a chat over pub/sub, where messages also spread through intermediate peers.

## Connecting to peers

```python
node.connect("example.com", 8080)   # a name or an IP address
node.disconnect(peer_id)            # RatsNoSuchPeerError if it was not connected

node.peer_count                     # how many peers are connected
node.peer_ids                       # their ids
node.peer_info(peer_id)             # PeerInfo(transport, transports, direction, address), or None
node.max_peers = 50                 # cap on peers, enforced on inbound; 0 is no cap
```

`connect()` returns immediately. A connection that succeeds arrives at
`on_peer_connected`. One that fails arrives at `on_dial_failed`, but only for an
IP address: a dial by host name fails silently. `on_peer_disconnected` reports
why a peer left as a `CloseReason`: `PEER_CLOSED`, `IDLE_TIMEOUT`,
`SLOW_CONSUMER`, and so on.

Each node listens on one port over both UDP and TCP. A dial tries UDP first and
also tries TCP if UDP does not succeed within 1.2 seconds.
`node.peer_info(peer_id).transport` shows which one was used.

What the node knows about itself: `node.local_id`, `node.listen_port` (the real
port when 0 was asked for), `node.observed_addresses` (its own addresses as
connected peers see them, which is how a node behind NAT learns its public
address) and `node.nat_mapping` (see [NAT traversal](#nat-traversal)).

There are three ways for nodes to find each other without knowing an address,
and they can be combined:

| | How it finds peers |
|---|---|
| `enable_mdns()` | multicast on the local network |
| `enable_dht(dht_port=0, discovery_key=None)` | the BitTorrent mainline DHT, worldwide. By default it looks for nodes with the same `protocol`; `dht_set_keys([...])` replaces the keys at any time, also while running |
| `enable_peer_exchange()` | connected peers tell each other about the peers they hold, so one contact is enough to find the rest |

### Who can connect

Every connection is encrypted and authenticated with the Noise protocol. When
`on_peer_connected` reports a peer id, the other side has proved it holds that
id's private key, and nobody in between can read or change the traffic.

What librats does not decide is whether you want that peer. Any node with the
same `protocol` string can connect to yours, and the string is not secret: it is
in your app, and the DHT lookup is derived from it. If only certain peers may
talk to your node, keep a list of the ids you trust, which stay fixed when the
peers use `data_dir`, and drop everyone else:

```python
trusted = {"3f2a…", "9c41…"}   # full 64-character ids

def on_connected(peer_id):
    if peer_id not in trusted:
        node.disconnect(peer_id)

node.on_peer_connected(on_connected)
```

The same goes for what peers send: a handler gets whatever bytes the peer chose
to send, so check them before using them.

## Sending messages

Messages travel on named **channels**: a name you choose, such as `"chat"` or
`"state"`. You send `bytes` (a `str` raises `TypeError`, so encode it first),
and the handler gets `bytes`.

```python
import json

node.on("state", lambda peer_id, data: apply(json.loads(data)))

node.send(peer_id, "state", json.dumps(state).encode())   # one peer; RatsNoSuchPeerError if not connected
node.broadcast("state", json.dumps(state).encode())       # every connected peer
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
and past its limit (8 MiB by default, `send_queue_limit`) the peer is
disconnected with `CloseReason.SLOW_CONSUMER`. To avoid that, check
`peer_writable(peer_id)` after each send, and once it returns `False`, wait for
`on_peer_writable`:

```python
from collections import deque

chunks = deque(...)

def pump(peer_id):
    while chunks:
        node.send(peer_id, "bulk", chunks.popleft())
        if not node.peer_writable(peer_id):
            return   # continue when on_peer_writable fires

node.on_peer_writable(pump)
```

For files, use [file transfer](#file-transfer) instead, which already does this.

### Live messages: audio and video

`lifetime_ms` makes a message **live**: it arrives within that time or not at
all, never partly and never twice, and it is not ordered with other messages.
An old video frame is useless, and this keeps a stale one from delaying the
next.

```python
node.send(peer_id, "video", frame, lifetime_ms=150)   # delivered within 150 ms or dropped
```

The longest lifetime is `LIVE_MAX_LIFETIME_MS` (30 s) and the largest payload is
`LIVE_MAX_PAYLOAD` (4 MiB). The receiver needs nothing special. An encoder can
adapt its bitrate to `path_stats(peer_id)`, which reports the bandwidth
estimate, round trip, loss, queued bytes and how many live messages expired.
The `on_peer_path` handler receives the same figures every 100 ms.

## More features

Each of these is off until enabled, and is enabled before `start()`:

| Feature | Enable | Then use |
|---|---|---|
| DHT discovery | `enable_dht(dht_port=0, discovery_key=None)` | `dht_set_keys([...])` |
| mDNS discovery | `enable_mdns()` | |
| Peer exchange | `enable_peer_exchange()` | |
| JSON messages | `enable_json()` | `on_json`, `once_json`, `off_json`, `send_json`, `broadcast_json` |
| Pub/sub (GossipSub) | `enable_pubsub()` | `subscribe`, `unsubscribe`, `publish` |
| File transfer | `enable_file_transfer(temp_dir=None)` | `on_file_offer`, `on_file_progress`, `on_file_complete`, `send_file`, `send_directory`, `accept_file`, `reject_file`, `pause_file`, `resume_file`, `cancel_file` |
| Port mapping | `enable_port_mapping(upnp=True, natpmp=True)` | |
| Hole punching | `enable_hole_punch(serve_rendezvous=True)` | `punch_peer(peer_id)`, `nat_mapping` |
| Relaying | `enable_relay(serve=False)` | `connect_via_relay(peer_id)` |
| Ping | `enable_ping()` | `peer_rtt_ms(peer_id)` |
| Reconnection | `enable_reconnect()` or `enable_reconnect_lost(lost_for_ms)` | `add_reconnect(host, port)`, `remove_reconnect(host, port)` |

### JSON messages and pub/sub

JSON messages are channels that carry values instead of bytes. `send_json`
encodes the value with `json.dumps`, and the handler receives it parsed. Values
come from other machines, so check their shape before trusting them.

Pub/sub works by topic instead of by peer. A published message reaches every
node subscribed to the topic, including through peers in between, so it scales
to groups where not everybody is connected to everybody.

```python
node.enable_json()
node.on_json("greeting", lambda peer_id, value: print(value["hello"]))

node.enable_pubsub()
node.subscribe("news", lambda peer_id, topic, data: print(topic, data.decode()))

node.start()
node.broadcast_json("greeting", {"hello": "world"})
node.publish("news", b"something happened")
```

Each topic has one handler; subscribing again replaces it. `on_json` adds a
handler, `once_json` adds one that is removed after its first message, and
`off_json` removes them all.

### File transfer

The sender offers a file or a directory. The receiver accepts it, choosing where
to save it, or rejects it. Both sides name a transfer by `(peer_id, transfer_id)`.

```python
import os

node.enable_file_transfer("./tmp")   # where partial downloads are kept

def on_offer(peer_id, transfer_id, name, size, is_directory):
    # `name` comes from the sender; basename() keeps a name like '../../x' in downloads/
    node.accept_file(peer_id, transfer_id, os.path.join("./downloads", os.path.basename(name)))

node.on_file_offer(on_offer)
node.on_file_progress(lambda p: print(p.transfer_id, p.status.name, f"{p.bytes_transferred}/{p.total_bytes}"))
node.on_file_complete(lambda peer_id, transfer_id, ok, path: print(transfer_id, ok, path))
node.start()

transfer_id = node.send_file(peer_id, "./video.mp4")   # RatsNoSuchPeerError / RatsNotFoundError
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
   involved needs `enable_hole_punch()`. It cannot work behind a symmetric NAT,
   which `node.nat_mapping == NatMapping.ENDPOINT_DEPENDENT` reports.
3. **Relaying** carries the connection through a peer both sides share. It stays
   encrypted end to end, so the relay cannot read it, and
   `peer_info(peer_id).transport` reports `Transport.RELAY`. Only nodes started
   with `enable_relay(serve=True)` carry other peers' traffic, because it costs
   them bandwidth.

```python
node.enable_port_mapping()
node.enable_hole_punch()
node.enable_relay()
node.start()

node.punch_peer(peer_id)   # RatsDeclinedError if there is nothing to do or nobody to help
```

With hole punching and relaying both enabled, a punch that cannot work falls
back to a relay by itself, and a relayed peer moves to a direct connection when
a later punch succeeds.

### Reconnection

`enable_reconnect()` redials peers that dropped, with growing pauses between
attempts. With `data_dir` the list survives a restart. `add_reconnect(host, port)`
adds an address to keep connected, and can be called while the node is running.

`enable_reconnect_lost(lost_for_ms)` does the same and also covers a peer that was
**lost** rather than one that **left**: a peer whose connection closed with
neither side closing it, because it went silent or stopped answering. Such a
peer is redialed where it was last seen for up to `lost_for_ms`. Use one of the
two, not both.

## Configuration

Everything is optional; the port is the one positional argument:

```python
RatsNode(
    8080,                     # listen port; default 0, any free port
    protocol="my-app/1.0",    # default "librats/1.0"
    data_dir="./state",       # identity, DHT table, reconnect list; default none
    max_peers=100,            # default 0, no cap
)
```

| Keyword | Default | What it does |
|---|---|---|
| `listen_port` | `0` | shared by UDP and TCP; 0 picks a free one |
| `protocol` | `"librats/1.0"` | app id bound into the handshake |
| `data_dir` | none | where the identity, DHT routing table and reconnect list are kept |
| `security` | `Security.NOISE` | `Security.PLAINTEXT` turns encryption off, for debugging only |
| `bind_address` | `"::"` | every interface, IPv4 and IPv6 |
| `dial_only` | `False` | no listener, outgoing connections only |
| `max_peers` | `0` | cap on connected peers, enforced on incoming ones; 0 is no cap |
| `transports` | both | `TransportMask.UDP`, `TransportMask.TCP`, or both |
| `preferred_transport` | `Transport.UDP` | which one a dial tries first |
| `transport_fallback_ms` | 1200 | how long the first transport tries alone before the other joins; `FALLBACK_NEVER` is never |
| `send_queue_limit` | 8 MiB | queue size past which a peer is dropped as `SLOW_CONSUMER` |
| `path_sample_ms` | `0` | how often `path_stats` is refreshed; 0 is only while an `on_peer_path` handler exists |
| `congestion_control` | `Congestion.BBR` | or `Congestion.RENO`, for UDP connections |
| `udp_receive_window` | 16 MiB | flow-control window of one UDP connection |
| `udp_receive_budget` | 64 MiB | out-of-order bytes all UDP connections may hold together |
| `udp_offload` | `True` | kernel segmentation offload for UDP, where available |
| `udp_idle_timeout_ms` | 45000 | silence after which a UDP peer counts as lost (`IDLE_TIMEOUT`) |
| `reactor_threads` | `1` | networking threads |
| `network_monitor` | `True` | react when interfaces or addresses change |

A combination no node can run with, such as `preferred_transport=Transport.TCP`
with `transports=TransportMask.UDP`, makes the constructor raise
`RatsInvalidArgError`.

## Lifecycle

```python
node = RatsNode(...)   # nothing runs yet
node.start()           # sockets open, features start
node.stop()            # every connection closes; start() works again
node.destroy()         # stopped and freed; any later call raises RatsError
```

- **`with RatsNode(...) as node:`** destroys the node when the block ends, also
  on an exception.
- **A node nobody destroys** is destroyed when it is garbage-collected or when
  the program exits.
- **A node cannot be stopped or destroyed from inside its own handler**: that
  would wait for the very thread the handler runs on. `stop()` and `destroy()`
  raise `RuntimeError` there. Signal the main thread instead, as the hello
  world does with an `Event`.
- **A restarted node keeps its id and features**, but not its connections:
  dial again, or let discovery and [reconnection](#reconnection) do it.

## Errors

A failed call raises a subclass of `RatsError`; its `error_code` names the cause:

```python
from librats_py import RatsNoSuchPeerError

try:
    node.send(peer_id, "chat", b"hi")
except RatsNoSuchPeerError:
    pass   # the peer left in the meantime
```

| Exception | Meaning |
|---|---|
| `RatsAlreadyStartedError` | this has to happen before `start()` |
| `RatsNotStartedError` | this has to happen after `start()` |
| `RatsNotEnabledError` | the feature was not enabled |
| `RatsNoSuchPeerError` | the peer is not connected |
| `RatsNotFoundError` | no such transfer, or a file to send that cannot be read |
| `RatsBindError` | the port is taken |
| `RatsInvalidArgError` | a bad argument, such as a malformed peer id, or a configuration that cannot work |
| `RatsDeclinedError` | a punch or relay attempt has nothing to do or nobody to help |
| `RatsError` | the base class; also what any call on a destroyed node raises |

Lookups for which "nothing" is a normal answer return `None` instead of raising:
`peer_info`, `path_stats`, `peer_rtt_ms`. Arguments are not converted for you:
ids, names and hosts are `str`, ports and sizes `int`, data `bytes`. Anything
else fails with a Python error such as `TypeError` before it reaches the
library.

## Logging and version

```python
from librats_py import LogLevel, set_log_level, set_log_file, version

set_log_level(LogLevel.WARN)     # DEBUG | INFO (default) | WARN | ERROR
set_log_file("./librats.log")    # also write to a file; set_log_file(None) stops it
print(version())                 # e.g. '3.0.5.0'
```

Logs go to the console: errors to stderr, everything else to stdout. These
settings apply to the whole library, every node in the process.
`version_info()` gives the version as numbers and `git_describe()` the exact
build.

## Examples

| | |
|---|---|
| [`chat`](https://github.com/librats/librats/blob/master/python/librats_py/examples/chat.py) | the chat above |
| [`gossipsub_chat`](https://github.com/librats/librats/blob/master/python/librats_py/examples/gossipsub_chat.py) | a chat over pub/sub |
| [`basic_client`](https://github.com/librats/librats/blob/master/python/librats_py/examples/basic_client.py) | channels and peer events, driven by typed commands |
| [`file_transfer`](https://github.com/librats/librats/blob/master/python/librats_py/examples/file_transfer.py) | sending and receiving files |

They are installed with the package and run as modules:

```bash
python -m librats_py.examples.chat alice
python -m librats_py.examples.gossipsub_chat 8080 alice general
python -m librats_py.examples.basic_client 8080
python -m librats_py.examples.file_transfer 8080 ./downloads
```

## Building from source

For a platform without a ready package, or to work on the bindings. You need
CMake 3.14 or newer and a C++17 compiler.

```bash
git clone https://github.com/librats/librats.git
cd librats/python
python build.py --build-native   # builds the shared library, copies it next to the package
pip install -e .
```

The library is looked for in the directories in `LIBRATS_LIBRARY_PATH`, then
next to the package, then in `build/lib`, `build/bin` and `build/` of the
repository, and finally by the system loader. The file is `rats.dll` on
Windows, `librats.dylib` on macOS, `librats.so` elsewhere. A MinGW build of
the DLL also needs `libstdc++-6.dll`, `libgcc_s_seh-1.dll` and
`libwinpthread-1.dll` beside it: Python does not search `PATH` for a DLL's
dependencies.

Tests: `pip install pytest`, then `python -m pytest librats_py/tests`. Tests
that need the library are skipped when it cannot be loaded.
[PYTHON_BINDINGS.md](https://github.com/librats/librats/blob/master/python/PYTHON_BINDINGS.md)
explains how the package is put together.

## License

MIT, see [LICENSE](https://github.com/librats/librats/blob/master/LICENSE).
