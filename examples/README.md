# librats examples

Small, self-contained programs that each demonstrate one capability of the
library, built directly on the public `Node` API.

## Building

Examples are **off by default**. Enable them with `-DRATS_BUILD_EXAMPLES=ON`
when configuring the main project:

```bash
cmake -B build -DRATS_BUILD_EXAMPLES=ON
cmake --build build -j
```

The BitTorrent example additionally needs `-DRATS_SEARCH_FEATURES=ON`.

Binaries land in `build/bin/examples/`. They can also be built standalone
against a source checkout:

```bash
cmake -S examples -B build-examples
cmake --build build-examples -j
```

## The examples

| Binary        | Source                        | Shows |
|---------------|-------------------------------|-------|
| `chat`        | `01_chat.cpp`                 | A bare `Node`: encrypted transport + raw channel messaging, manual dialing. |
| `pubsub`      | `02_pubsub.cpp`               | The `PubSub` (GossipSub) subsystem — topic mesh that relays across hops. |
| `typed_messaging` | `03_typed_messaging.cpp`  | `MessageJson` typed JSON messages, keyed by the authenticated sender. |
| `file_transfer` | `04_file_transfer.cpp`      | `FileTransfer` — streaming a file with CRC32/SHA-256 integrity + progress. |
| `dht_discovery` | `05_dht_discovery.cpp`      | `DhtDiscovery` — automatic peer discovery over the Kademlia DHT. |
| `bittorrent_download` | `06_bittorrent_download.cpp` | Downloading a magnet link (requires `RATS_SEARCH_FEATURES`). |
| `full_chat`   | `07_full_chat.cpp`            | "Batteries-included" chat: DHT + mDNS + PEX discovery, reconnection, ping, and pub/sub — peers find each other with no addresses typed in. |

Each source file's header comment documents its command-line usage. A typical
two-node run:

```bash
./build/bin/examples/chat 9000                 # terminal 1 (listener)
./build/bin/examples/chat 9001 127.0.0.1 9000  # terminal 2 (dials the first)
```

For a fuller, interactive application wiring up every subsystem at once, see the
`rats-client` reference binary (`src/main.cpp`), also built when
`RATS_BUILD_EXAMPLES=ON`.
