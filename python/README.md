# librats Python Bindings

Python bindings for the **librats** peer-to-peer networking library. They target
the librats C ABI (`src/bindings/rats.h`) via `ctypes` and expose a high-level
`RatsClient` for P2P messaging, pub/sub, typed JSON messaging, file transfer,
discovery (DHT / mDNS), NAT port mapping, ping/RTT and automatic reconnection.

> **Migrating from the old bindings?** The C ABI was rewritten. See
> [Migration](#migration-from-the-old-api) for the old → new mapping and the
> features that were removed.

## Prerequisites

1. Build the librats C shared library first (see main README / build script).
2. Python 3.7+.

## Installing

```bash
cd python
pip install -e .              # development install
# or: pip install -e ".[dev]" # with test/lint tooling
```

Build the native library and copy it next to the package:

```bash
cd python
python build.py --build-native    # CMake: -DRATS_SHARED_LIBRARY=ON
```

## Core concepts

* A `RatsClient` wraps a single librats node (`rats_t`).
* **Register callbacks and enable subsystems _before_ `start()`.** Enabling a
  subsystem after start raises `RatsAlreadyStartedError`; using a subsystem
  before enabling it raises `RatsNotEnabledError`.
* Peer ids are 64-character lowercase hex strings.
* Callbacks fire on an internal reactor thread — keep them short and
  non-blocking. Exceptions raised inside a callback are logged, not propagated
  into C.
* Transport security defaults to **Noise XX** (encrypted + authenticated).

## Quick start

### Basic messaging (named channel, raw bytes)

```python
from librats_py import RatsClient

with RatsClient(listen_port=8080) as client:
    client.on_peer_connected(lambda pid: print("connected:", pid))
    client.on("chat", lambda peer_id, data: print(peer_id, data.decode()))

    client.start()
    print("local id:", client.local_id)

    client.connect("192.168.1.100", 8081)
    client.broadcast("chat", b"Hello, P2P world!")
    input("Press Enter to exit...")
```

### Configured node

```python
from librats_py import RatsClient, Security

client = RatsClient(
    listen_port=8080,
    security=Security.NOISE,        # or Security.PLAINTEXT
    data_dir="./state",             # persistent identity + subsystem state
    protocol_name="myapp",
    protocol_version="1.0",
    max_peers=50,
)
```

### Pub/sub (GossipSub)

```python
with RatsClient(8080) as client:
    client.enable_pubsub()                                   # before start()
    client.subscribe("room", lambda pid, topic, data: print(topic, data))
    client.start()
    client.publish("room", b"Hello everyone!")
```

### Typed JSON messaging

```python
with RatsClient(8080) as client:
    client.enable_json()                                     # before start()
    client.on_json("greeting", lambda pid, payload: print(pid, payload))
    client.start()
    client.broadcast_json("greeting", {"hi": "there"})
```

### File transfer (push model)

```python
with RatsClient(8080) as client:
    client.enable_file_transfer(temp_dir="./downloads")      # before start()

    def on_offer(peer_id, transfer_id, name, size, is_dir):
        client.accept_file(peer_id, transfer_id, f"./downloads/{name}")

    client.on_file_offer(on_offer)
    client.on_file_progress(lambda tid, pid, done, total, status:
                            print(tid, done, total, status))
    client.on_file_complete(lambda tid, ok, path: print(tid, ok, path))
    client.start()

    # Sender side:
    transfer_id = client.send_file(peer_id, "/path/to/file.txt")
    # transfer_id = client.send_directory(peer_id, "/path/to/dir")
```

### Discovery, NAT, ping, reconnect

```python
with RatsClient(8080) as client:
    client.enable_dht(dht_port=0, discovery_key="myapp")     # before start()
    client.enable_mdns()
    client.enable_port_mapping(enable_upnp=True, enable_natpmp=True)
    client.enable_ping()
    client.enable_reconnect()
    client.start()

    client.add_reconnect("192.168.1.100", 8081)
    rtt = client.peer_rtt_ms(some_peer_id)                   # -1 if unknown
```

## API reference

### Construction

```python
RatsClient(listen_port=0, *, enable_listen=True, bind_address=None,
           security=Security.NOISE, data_dir=None,
           protocol_name=None, protocol_version=None, max_peers=0)
```

### Lifecycle / identity

| Method / property | Description |
| --- | --- |
| `start()` / `stop()` | Start / stop the node |
| `is_running() -> bool` | Whether started |
| `destroy()` | Explicitly destroy (else on GC) |
| `local_id -> str` | Our 64-hex peer id |
| `listen_port -> int` | Actual listen port |
| `protocol_name` / `protocol_version` | Handshake identity |

### Connections / peers

`connect(host, port)`, `peer_count() -> int`, `peer_ids() -> list[str]`,
`set_max_peers(n)`, `get_max_peers() -> int`.

### Raw messaging

`send(peer_id, channel, data: bytes)`, `broadcast(channel, data: bytes)`,
`on(channel, cb)` where `cb(peer_id: str, data: bytes)`.

### Peer events

`on_peer_connected(cb)`, `on_peer_disconnected(cb)` where `cb(peer_id: str)`.

### Pub/sub

`enable_pubsub()`, `subscribe(topic, cb)` (`cb(peer_id, topic, data: bytes)`),
`unsubscribe(topic)`, `publish(topic, data: bytes)`.

### Typed JSON

`enable_json()`, `on_json(type, cb)`, `once_json(type, cb)`, `off_json(type)`
(`cb(peer_id, payload)`), `send_json(peer_id, type, payload)`,
`broadcast_json(type, payload)`. Payloads are JSON-encoded (dict/list/etc).

### File transfer

`enable_file_transfer(temp_dir=None)`, `on_file_offer(cb)`,
`on_file_progress(cb)`, `on_file_complete(cb)`, `send_file(peer_id, path) -> int`,
`send_directory(peer_id, dir_path) -> int`,
`accept_file(peer_id, transfer_id, dest_path)`,
`reject_file(peer_id, transfer_id)`, `cancel_file(...)`, `pause_file(...)`,
`resume_file(...)`.

Callback signatures:

* offer: `(peer_id, transfer_id, name, size, is_directory)`
* progress: `(transfer_id, peer_id, bytes_transferred, total_bytes, status)`
  where `status` is a `FileTransferStatus`
* complete: `(transfer_id, success, path)`

### Discovery / NAT / liveness / reconnect

`enable_dht(dht_port=0, discovery_key=None)`, `enable_mdns()`,
`enable_port_mapping(enable_upnp=True, enable_natpmp=True)`, `enable_ping()`,
`peer_rtt_ms(peer_id) -> int`, `enable_reconnect()`,
`add_reconnect(host, port)`, `remove_reconnect(host, port)`.

### Logging / info (static)

`RatsClient.set_log_level(LogLevel)`, `RatsClient.set_log_file(path|None)`,
`RatsClient.get_version_string()`, `RatsClient.get_version() -> VersionInfo`,
`RatsClient.get_git_describe()`, `RatsClient.get_abi() -> int`,
`RatsClient.error_str(code) -> str`.

### Enums

* `Security` — `NOISE`, `PLAINTEXT`
* `LogLevel` — `DEBUG`, `INFO`, `WARN`, `ERROR`
* `FileTransferStatus` — `PENDING`, `ACTIVE`, `PAUSED`, `COMPLETED`, `FAILED`, `CANCELLED`
* `ErrorCode` (`rats_error_t`) — `OK`, `INVALID_ARG`, `NOT_STARTED`, `ALREADY_STARTED`, `NOT_ENABLED`, `NO_SUCH_PEER`, `BIND`, `INTERNAL`

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

Integration tests require the native shared library to be built and importable.

## Migration from the old API

| Old binding | New binding |
| --- | --- |
| `set_connection_callback` / `set_disconnect_callback` | `on_peer_connected` / `on_peer_disconnected` |
| `send_string` / `broadcast_string` / `send_binary` / `broadcast_binary` | `send(peer, channel, bytes)` / `broadcast(channel, bytes)` + `on(channel, cb)` |
| `send_json` / `broadcast_json` + `set_json_callback` | `enable_json` + `send_json(peer, type, payload)` / `broadcast_json(type, payload)` + `on_json` |
| `subscribe_to_topic` / `publish_to_topic` + topic callbacks | `enable_pubsub` + `subscribe(topic, cb)` / `publish(topic, bytes)` |
| `send_file` / `accept_file_transfer` (string ids) | `enable_file_transfer` + `send_file`/`send_directory` (returns int id) + `on_file_offer/progress/complete` |
| `start_dht_discovery` | `enable_dht` (before start) |
| `start_mdns_discovery` | `enable_mdns` (before start) |
| `get_our_peer_id` | `local_id` |
| `get_peer_count` / `get_peer_ids` | `peer_count` / `peer_ids` |
| `set_max_peers` / `get_max_peers` | same names |
| `set_log_level(name_str)` | `set_log_level(LogLevel)` |

### Removed features

The following no longer exist in the C ABI and were dropped from the Python API:

* **ICE / STUN / TURN** NAT traversal — use `enable_port_mapping` (UPnP/NAT-PMP).
* **Encryption enable/keys** — security is fixed at construction via the
  `security` parameter (`Security.NOISE` / `Security.PLAINTEXT`).
* **Configuration load/save** — use the `data_dir` constructor argument for
  persistent identity and subsystem state.
* **Granular logging** (colours, timestamps, rotation, retention, per-node
  console toggles) — only `set_log_level` / `set_log_file` remain.
* **Historical peers** and **automatic-discovery toggles** — use
  `enable_reconnect` / `add_reconnect` and `enable_dht` / `enable_mdns`.
* **Statistics JSON** (connection / gossipsub / file-transfer) — removed.

## Library loading

The bindings search for the shared library next to the package, in `../build`
(and `build/lib`, `build/bin`), system library paths, and `LD_LIBRARY_PATH` /
`PATH`. Platform names: `rats.dll`/`librats.dll` (Windows),
`librats.dylib` (macOS), `librats.so` (Linux). `python build.py --build-native`
copies the freshly built library next to the package automatically.

## License

MIT — see the LICENSE file.
