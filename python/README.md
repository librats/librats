# librats — Python bindings

Python bindings for [librats](../README.md), a C++17 peer-to-peer networking
library. They drive the C ABI (`src/librats/bindings/rats.h`) through `ctypes`
and expose a high-level `RatsNode`.

## The model

A `RatsNode` is one librats node. On its own it gives you secure transport
(Noise XX over TCP **or** the library's reliable stream over UDP, both on the
same port), a self-certifying peer id, manual dialing, and raw messaging on named
channels — nothing else. Discovery (DHT/mDNS), pub/sub, typed JSON messaging,
file transfer, NAT port mapping, hole punching, RTT probing and reconnection are
**opt-in subsystems**: you pay only for what you turn on.

Two rules follow from that:

- **Enable subsystems and register callbacks before `start()`.** Enabling after
  start raises `RatsAlreadyStartedError`; using a subsystem before its enable
  raises `RatsNotEnabledError`.
- **Callbacks fire on an internal reactor thread.** Keep them short and
  non-blocking. An exception raised inside one is logged, never propagated into C.

Fallible calls raise a `RatsError` subclass; pure getters are properties. Peer
ids are 64-character lowercase hex strings.

## Installing

Python 3.7+. The bindings need the librats **shared** library.

```bash
cd python
pip install -e .                  # development install
python build.py --build-native    # CMake -DRATS_SHARED_LIBRARY=ON, copied next to the package
```

The loader looks next to the package, in `../build` (`build/lib`, `build/bin`),
the system library paths, and `LD_LIBRARY_PATH` / `PATH`. Names are
`rats.dll`/`librats.dll` (Windows), `librats.dylib` (macOS), `librats.so` (Linux).

## Quick start

```python
from librats_py import RatsNode

with RatsNode(8080, data_dir="./state") as node:
    # Everything below happens before start().
    node.on_peer_connected(lambda peer: print("+", peer))
    node.on("chat", lambda peer, data: print(peer, data.decode()))
    node.enable_dht()          # find peers on the mainline DHT
    node.enable_mdns()         # …and on the local network

    node.start()
    print("local id:", node.local_id, "port:", node.listen_port)

    node.connect("192.168.1.100", 8081)
    node.broadcast("chat", b"Hello, P2P world!")
    input("Press Enter to exit...")
```

### Configured node

```python
from librats_py import RatsNode, Security, Transport

node = RatsNode(
    listen_port=8080,
    security=Security.NOISE,        # or Security.PLAINTEXT
    data_dir="./state",             # persistent identity + subsystem state
    protocol="myapp/1.0",           # handshake app id; peers must match
    max_peers=50,
    preferred_transport=Transport.UDP,
    transport_fallback_ms=1200,     # 0 disables the TCP fallback race
)
```

### Pub/sub (GossipSub)

```python
with RatsNode(8080) as node:
    node.enable_pubsub()
    node.subscribe("room", lambda peer, topic, data: print(topic, data))
    node.start()
    node.publish("room", b"Hello everyone!")
```

### Typed JSON messaging

Payloads are JSON-encoded on the way out and parsed on the way in.

```python
with RatsNode(8080) as node:
    node.enable_json()
    node.on_json("greeting", lambda peer, payload: print(peer, payload["hi"]))
    node.start()
    node.broadcast_json("greeting", {"hi": "there"})
```

### File transfer (push model)

```python
with RatsNode(8080) as node:
    node.enable_file_transfer(temp_dir="./tmp")   # in-progress downloads live here

    node.on_file_offer(lambda peer, tid, name, size, is_dir:
                       node.accept_file(peer, tid, f"./downloads/{name}"))
    node.on_file_progress(lambda tid, peer, done, total, status:
                          print(tid, done, total, status))
    node.on_file_complete(lambda tid, ok, path: print(tid, ok, path))
    node.start()

    transfer_id = node.send_file(peer_id, "/path/to/file.txt")   # 0 on failure
    # transfer_id = node.send_directory(peer_id, "/path/to/dir")
```

### NAT traversal

Port forwarding is the easy path; hole punching covers the networks where it
fails. Punching needs peers that relay the rendezvous — a mesh in which nobody
relays cannot punch at all.

```python
from librats_py import NatMapping

with RatsNode(8080) as node:
    node.enable_port_mapping()          # UPnP IGD + NAT-PMP
    node.enable_hole_punch()            # relays other peers' rendezvous by default
    node.enable_relay()                 # last resort, for pairs a punch cannot reach
    node.start()

    node.punch_peer(peer_id)            # success arrives as on_peer_connected
    if node.nat_mapping is NatMapping.ENDPOINT_DEPENDENT:
        print("symmetric NAT — punching cannot work, but a relay still can")
```

`enable_relay()` routes the connection itself through a node both ends already
reach, which is the only way through a symmetric NAT. It stays encrypted end to
end — the relay moves ciphertext — and the peer behaves like any other, except
that :meth:`peer_transport` reports ``Transport.RELAY``. With both enabled the
ladder runs itself: a punch that cannot work falls back to a relay, and a relayed
peer keeps trying to become a direct one. Pass ``serve_as_relay=True`` to also
carry OTHER peers' connections, which spends real bandwidth and is off by default.

### Liveness and reconnection

```python
with RatsNode(8080) as node:
    node.enable_ping()
    node.enable_reconnect()
    node.start()

    node.add_reconnect("192.168.1.100", 8081)
    rtt = node.peer_rtt_ms(peer_id)     # -1 if unknown
```

## API reference

### Construction

```python
RatsNode(listen_port=0, *, enable_listen=True, bind_address=None,
         security=Security.NOISE, data_dir=None, protocol=None, max_peers=0,
         enable_tcp=True, enable_udp=True,
         preferred_transport=Transport.UDP, transport_fallback_ms=1200)
```

### Lifecycle

`start()` · `stop()` · `destroy()` · `is_running() -> bool` · context manager
(`with RatsNode(...) as node:` releases the node on exit)

### Properties

| Property | Description |
| --- | --- |
| `local_id -> str` | our 64-hex self-certifying peer id |
| `listen_port -> int` | the bound port (resolved when 0 was requested) |
| `protocol -> str` | handshake app id, e.g. `"librats/1.0"` |
| `transports -> int` | `TransportMask` bitmask of what is actually running |
| `peer_count -> int` | currently-connected peers |
| `peer_ids -> list[str]` | their hex ids |
| `max_peers -> int` | established-peer cap (0 = unlimited); settable |
| `nat_mapping -> NatMapping` | what the mesh has shown about our own NAT |

### Connections

`connect(host, port)` · `peer_transport(peer_id) -> Transport | None` ·
`peer_transports(peer_id) -> int | None`

### Raw channel messaging

`send(peer_id, channel, data: bytes)` · `broadcast(channel, data: bytes)` ·
`on(channel, cb)` where `cb(peer_id: str, data: bytes)`

### Peer events

`on_peer_connected(cb)` · `on_peer_disconnected(cb)` where `cb(peer_id: str)`

### Subsystems (enable before start)

| Subsystem | Enable | Then |
| --- | --- | --- |
| DHT discovery | `enable_dht(dht_port=0, discovery_key=None)` | — |
| mDNS discovery | `enable_mdns()` | — |
| NAT port mapping | `enable_port_mapping(enable_upnp=True, enable_natpmp=True)` | — |
| Hole punching | `enable_hole_punch(serve_as_relay=True)` | `punch_peer(peer_id)`, `nat_mapping` |
| Relaying | `enable_relay(serve_as_relay=False)` | `connect_via_relay(peer_id)` |
| Pub/sub | `enable_pubsub()` | `subscribe(topic, cb)`, `unsubscribe(topic)`, `publish(topic, data)` |
| Typed JSON | `enable_json()` | `on_json(type, cb)`, `once_json(type, cb)`, `off_json(type)`, `send_json(peer, type, payload)`, `broadcast_json(type, payload)` |
| File transfer | `enable_file_transfer(temp_dir=None)` | `on_file_offer/on_file_progress/on_file_complete`, `send_file`, `send_directory`, `accept_file`, `reject_file`, `cancel_file`, `pause_file`, `resume_file` |
| Liveness | `enable_ping()` | `peer_rtt_ms(peer_id)` — ms, or -1 if unknown |
| Reconnection | `enable_reconnect()` | `add_reconnect(host, port)`, `remove_reconnect(host, port)` |

File-transfer callback signatures:

* offer: `(peer_id, transfer_id, name, size, is_directory)`
* progress: `(transfer_id, peer_id, bytes_transferred, total_bytes, status)`
  where `status` is a `FileTransferStatus`
* complete: `(transfer_id, success, path)`

### Module-level helpers

These need no node: `set_log_level(LogLevel)`, `set_log_file(path | None)`,
`version() -> str`, `version_info() -> VersionInfo`, `git_describe() -> str`,
`abi() -> int`, `error_str(code) -> str`.

### Enums

* `Security` — `NOISE`, `PLAINTEXT`
* `Transport` — `TCP`, `UDP`
* `TransportMask` — `TCP` (0x1), `UDP` (0x2)
* `NatMapping` — `UNKNOWN`, `OPEN`, `ENDPOINT_INDEPENDENT`, `ENDPOINT_DEPENDENT`
* `LogLevel` — `DEBUG`, `INFO`, `WARN`, `ERROR`
* `FileTransferStatus` — `PENDING`, `ACTIVE`, `PAUSED`, `COMPLETED`, `FAILED`, `CANCELLED`
* `ErrorCode` (`rats_error_t`) — `OK`, `INVALID_ARG`, `NOT_STARTED`,
  `ALREADY_STARTED`, `NOT_ENABLED`, `NO_SUCH_PEER`, `BIND`, `INTERNAL`

### Exceptions

`RatsError` (base) with subclasses keyed off `rats_error_t`:
`RatsInvalidArgError`, `RatsNotStartedError`, `RatsAlreadyStartedError`,
`RatsNotEnabledError`, `RatsNoSuchPeerError`, `RatsBindError`,
`RatsConnectionError`.

## Examples

```bash
python -m librats_py.examples.basic_client 8080
python -m librats_py.examples.file_transfer 8080 ./downloads
python -m librats_py.examples.gossipsub_chat 8080 alice general
```

## Testing

```bash
pip install -e ".[dev]"
python -m pytest librats_py/tests/
```

The suites skip themselves when the native shared library cannot be loaded.

## License

MIT — see [LICENSE](../LICENSE).
