# librats — Python bindings

Python bindings for [librats](../README.md). They call the library's C ABI
(`src/librats/bindings/rats.h`) through `ctypes`, so there is nothing to compile
on the Python side — only the librats shared library itself.

## The model

A `RatsNode` is one librats node. On its own it gives you an encrypted
connection to any peer you dial (Noise XX, over UDP or TCP on the same port), a
peer id derived from the node's key, and raw messages on named channels.
Discovery, NAT traversal, pub/sub, JSON messages, file transfer, ping and
reconnection are subsystems you switch on one by one.

Three rules follow:

- **Enable subsystems and register callbacks before `start()`.** Enabling after
  start raises `RatsAlreadyStartedError`; registering a peer or channel callback
  after start does too. Using a subsystem you did not enable raises
  `RatsNotEnabledError`.
- **Callbacks run on a librats thread.** Keep them short. An exception raised in
  one is printed to stderr; it never reaches the library.
- **Errors are exceptions.** Each `rats_error_t` code has its own `RatsError`
  subclass (table below). Peer ids are 64-character lowercase hex strings.

## Installing

Python 3.8 or newer, and the librats **shared** library:

```bash
cd python
python build.py --build-native    # CMake, -DRATS_SHARED_LIBRARY=ON, into build/python,
                                  # then copies the library next to the package
pip install -e .
```

The loader tries, in order: the directories in `LIBRATS_LIBRARY_PATH`, the
package directory, `build/lib`, `build/bin` and `build/` of the repository, and
finally the system loader by bare name. The file is `rats.dll` or `librats.dll`
on Windows, `librats.dylib` on macOS, `librats.so` elsewhere. A MinGW build of
the DLL also needs `libstdc++-6.dll`, `libgcc_s_seh-1.dll` and
`libwinpthread-1.dll` beside it: Python does not search `PATH` for a DLL's
dependencies.

## Quick start

```python
from librats_py import RatsNode

with RatsNode(8080, protocol="myapp/1.0", data_dir="./state") as node:
    node.on_peer_connected(lambda peer: print("+", peer))
    node.on_peer_disconnected(lambda peer, why: print("-", peer, why.name))
    node.on("chat", lambda peer, data: print(peer[:8], data.decode()))
    node.enable_mdns()                       # find peers on the local network

    node.start()
    print("id", node.local_id, "port", node.listen_port)
    node.connect("192.168.1.100", 8081)      # or wait for discovery
    node.broadcast("chat", b"hello")
    input("Enter to quit\n")
```

`with` destroys the node on exit. Without it, call `destroy()` (or let the
garbage collector do it).

## Configuration

Every keyword of `RatsNode(...)` maps to a field of `rats_config_t`; leave one
out and the library default applies.

| Keyword | Default | Meaning |
| --- | --- | --- |
| `listen_port` | 0 | port both transports listen on; 0 picks a free one |
| `protocol` | `"librats/1.0"` | app id bound into the handshake; peers with a different one cannot connect |
| `data_dir` | none | keeps the identity (and DHT table, reconnect list) across runs; without it the id is new every run |
| `security` | `Security.NOISE` | `Security.PLAINTEXT` turns encryption off |
| `bind_address` | `"::"` | interface to listen on (dual-stack by default) |
| `dial_only` | `False` | no listener at all |
| `max_peers` | 0 | cap on established peers, enforced on inbound; 0 = none. Also a settable property |
| `transports` | both | `TransportMask.TCP`, `TransportMask.UDP`, or both |
| `preferred_transport` | `Transport.UDP` | which one a dial tries first |
| `transport_fallback_ms` | 1200 | how long the first transport dials alone before the other joins; `FALLBACK_NEVER` disables it |
| `send_queue_limit` | 8 MiB | bytes a peer's queue may hold before a sender that keeps going loses the peer (see Backpressure) |
| `path_sample_ms` | off | how often `path_stats()` is refreshed; an `on_peer_path` callback turns it on at 100 ms |
| `congestion_control` | `Congestion.BBR` | `Congestion.RENO` for a loss-based controller (UDP only) |
| `udp_receive_window` | 16 MiB | ceiling of one UDP connection's flow-control window |
| `udp_receive_budget` | 64 MiB | out-of-order bytes all UDP connections together may hold |
| `udp_offload` | `True` | kernel UDP segmentation offload where available |
| `reactor_threads` | 1 | I/O threads |
| `network_monitor` | `True` | watch the host for interface and address changes |

An impossible combination — no transport, or a preferred transport you turned
off — raises `RatsInvalidArgError` from the constructor.

## Messages

```python
node.send(peer_id, "chat", b"hi")              # one peer
node.broadcast("chat", b"hi everyone")         # every connected peer
node.send(peer_id, "video", frame, lifetime_ms=150)
```

A send returns once the message is queued; it does not wait for delivery.
Without `lifetime_ms` a message is reliable and arrives in order with
everything else the node sends on its channels. With `lifetime_ms` it is a
**live** message: it is worth delivering only within that many milliseconds, is
repaired while it can still make it, and is dropped whole once it cannot. Live
messages are never delivered partly or twice and are not ordered, so number them
if order matters. They are meant for audio and video frames; the limits are
`LIVE_MAX_LIFETIME_MS` (30 s) and `LIVE_MAX_PAYLOAD` (1 MiB). The receiving
`on()` handler is the same for both kinds.

### Backpressure

`send()` accepts a message of any size, but a peer whose queue is already past
`send_queue_limit` when you send more is dropped with
`CloseReason.SLOW_CONSUMER`. To avoid that when sending in bulk:

```python
node.send(peer_id, "bulk", chunk)
if not node.peer_writable(peer_id):
    # stop here; resume when on_peer_writable(peer_id) fires
    ...
```

### Path statistics

For a sender that sizes its output to the link (a live encoder),
`path_stats(peer_id)` returns a `PathStats`: the congestion controller's
`bandwidth_bps`, `srtt_us`, `queued_bytes`, `loss`, and counts of live messages
sent and expired. Over TCP most figures come from the kernel and exist only on
Linux. `on_peer_path(cb)` delivers the same samples periodically.

## Peers

```python
node.peer_count, node.peer_ids
info = node.peer_info(peer_id)      # None if not connected
info.transport                      # Transport.UDP / TCP / RELAY
info.direction                      # Direction.OUTBOUND / INBOUND
info.address                        # "203.0.113.5:8080", "" until known
info.transports                     # what the peer says it accepts
node.disconnect(peer_id)
node.on_dial_failed(lambda address: print("unreachable", address))
```

`on_peer_disconnected` passes a `CloseReason`. A peer that left can be redialed;
`SLOW_CONSUMER` means this node sent faster than the link drained, and redialing
only repeats that.

## Subsystems

All of these are enabled before `start()`.

| Subsystem | Enable | Then |
| --- | --- | --- |
| DHT discovery | `enable_dht(dht_port=0, discovery_key=None)` | peers found are dialed automatically |
| mDNS discovery | `enable_mdns()` | — |
| Peer exchange | `enable_peer_exchange()` | peers share the addresses of peers they hold |
| Port mapping | `enable_port_mapping(upnp=True, natpmp=True)` | — |
| Hole punching | `enable_hole_punch(serve_rendezvous=True)` | `punch_peer(peer_id)`, `nat_mapping`, `observed_addresses` |
| Relaying | `enable_relay(serve=False)` | `connect_via_relay(peer_id)` |
| Pub/sub | `enable_pubsub()` | `subscribe(topic, cb)`, `unsubscribe(topic)`, `publish(topic, data)` |
| JSON messages | `enable_json()` | `on_json`, `once_json`, `off_json`, `send_json`, `broadcast_json` |
| File transfer | `enable_file_transfer(temp_dir=None)` | see below |
| Ping | `enable_ping()` | `peer_rtt_ms(peer_id)` — `None` until measured |
| Reconnection | `enable_reconnect()` | `add_reconnect(host, port)`, `remove_reconnect(host, port)` |
| BitTorrent | `enable_bittorrent(...)` | `bt_add_magnet`, `bt_add_torrent_file`, `bt_remove_torrent` — only in libraries built with `RATS_SEARCH_FEATURES` |

### NAT traversal

```python
node.enable_port_mapping()       # ask the router first
node.enable_hole_punch()         # punch through a peer both sides share
node.enable_relay()              # last resort: route through such a peer
node.start()
...
node.punch_peer(peer_id)         # success arrives as on_peer_connected
```

Hole punching needs every node involved to have it enabled, and some node in
the mesh to pass rendezvous messages along (`serve_rendezvous=True`, the
default). It cannot work from behind a symmetric NAT
(`node.nat_mapping == NatMapping.ENDPOINT_DEPENDENT`); a relay can. A relayed
peer stays encrypted end to end and `peer_info()` reports `Transport.RELAY`.
With both enabled, a punch that cannot work falls back to a relay, and a relayed
peer is moved to a direct connection when a later punch succeeds.
`enable_relay(serve=True)` also carries other peers' connections, which costs
this node their bandwidth; nobody does it unless asked.

`punch_peer` and `connect_via_relay` raise `RatsDeclinedError` when there is
nothing to do or nothing to try with (already connected, already trying, no peer
to help).

### JSON messages

```python
node.enable_json()
node.on_json("greeting", lambda peer, value: print(value["hi"]))
node.start()
node.broadcast_json("greeting", {"hi": "there"})
```

Values are encoded with `json.dumps` and handed to handlers parsed. `on_json`
adds a handler and may be called while running; `once_json` removes it after
its first message.

### File transfer

The sender offers, the receiver accepts or rejects.

```python
node.enable_file_transfer(temp_dir="./partial")
node.on_file_offer(lambda peer, tid, name, size, is_dir:
                   node.accept_file(peer, tid, f"./downloads/{name}"))
node.on_file_progress(lambda p: print(p.transfer_id, p.bytes_transferred, p.total_bytes,
                                      p.status.name))
node.on_file_complete(lambda peer, tid, ok, path: print(tid, ok, path))
node.start()

tid = node.send_file(peer_id, "report.pdf")          # or send_directory()
node.pause_file(peer_id, tid); node.resume_file(peer_id, tid); node.cancel_file(peer_id, tid)
```

A transfer is named by the pair (peer, transfer id). The offer, progress and
complete callbacks are one each; registering again replaces the previous one.
`on_file_progress` receives a `FileProgress` with direction, status, byte and
file counts and a smoothed rate.

## Module functions

`set_log_level(LogLevel)`, `set_log_file(path or None)`, `version()`,
`version_info()`, `git_describe()`, `abi()`, `error_str(code)`.

## Errors

| Exception | `ErrorCode` | Raised when |
| --- | --- | --- |
| `RatsInvalidArgError` | `INVALID_ARG` | malformed peer id, bad JSON, impossible config |
| `RatsNotStartedError` | `NOT_STARTED` | `connect()` before `start()` |
| `RatsAlreadyStartedError` | `ALREADY_STARTED` | enabling or registering a callback after `start()` |
| `RatsNotEnabledError` | `NOT_ENABLED` | using a subsystem that was not enabled |
| `RatsNoSuchPeerError` | `NO_SUCH_PEER` | the peer is not connected |
| `RatsNotFoundError` | `NOT_FOUND` | no such file transfer, or a file to offer that cannot be read |
| `RatsDeclinedError` | `DECLINED` | a punch or relay attempt has nothing to do |
| `RatsBindError` | `BIND` | `start()` could not open its sockets |

All derive from `RatsError`, whose `error_code` holds the code.

## Examples

```bash
python -m librats_py.examples.basic_client 8080
python -m librats_py.examples.file_transfer 8080 ./downloads
python -m librats_py.examples.gossipsub_chat 8080 alice general
```

## Tests

```bash
pip install pytest
python -m pytest librats_py/tests
```

Tests that need the shared library are marked `native` and skipped when it
cannot be loaded.

## License

MIT — see [LICENSE](../LICENSE).
