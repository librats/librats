# bench — librats' benchmark suite

Every benchmark here answers the same shape of question: **is the current
implementation actually better than what it replaced (or than the library we are
measuring ourselves against), and by how much?** So each suite links its own
subject *and* a reference side into one binary and prints them side by side.

## Layout

```
bench/
├── framework/        the harness — project-agnostic, no librats in it
│   ├── bench.h           timing loop, calibration, comparison report
│   └── alloc_track.*     global operator new/delete counters
├── support/          scaffolding a suite needs to exercise librats
│   ├── net_mock.h       mocked kernel socket buffers (exact syscall counts)
│   └── json_data.h      dataset generators
├── baseline/         frozen copies of what we are measured against
│   ├── stable_json.*        librats::Json, previous implementation
│   └── legacy_buffers.*     receive/send buffers, pre-5d64343
├── suites/           the benchmarks themselves — one file, one executable
│   ├── bench_json.cpp    Json vs nlohmann vs RapidJSON vs previous Json
│   ├── bench_complex.cpp Json, one deliberately nasty document
│   ├── bench_mem.cpp     resident heap of a parsed DOM
│   ├── bench_rx.cpp      receive path, current vs pre-5d64343
│   ├── bench_tx.cpp      send path, current vs pre-5d64343
│   ├── bench_poller.cpp  readiness notifications: how many, and what each costs
│   ├── bench_dht.cpp     keyspace primitives vs libtorrent's
│   ├── bench_crypto.cpp  Noise primitives vs the noise-c reference
│   └── bench_transport.cpp  TCP vs the reliable-UDP stream, two live Nodes
│                            (loopback, or between two hosts over a real path)
└── CMakeLists.txt
```

The four top-level directories are four different *kinds* of code, and keeping
them apart is the point:

* **`framework/`** knows nothing about librats and never will. It is the thing you
  could copy into another project.
* **`support/`** is librats-specific, but it is not under test — it is the rig the
  subject is mounted in (a fake socket, a data generator).
* **`baseline/`** is code that already shipped, frozen in its own namespace
  (`librats_stable`, `librats_legacy`) so old and new can link into one binary.
  **Never "fix" anything in here** — the whole point is that it behaves exactly
  like the code it is standing in for. Regenerate it from git, don't edit it.
* **`suites/`** is where a benchmark actually lives, and it should read as the
  experiment: what is compared, under what workload, measured how.

Everything includes from the `bench/` root, so an include path says which layer it
belongs to: `#include "framework/bench.h"`, `"support/net_mock.h"`,
`"baseline/stable_json.h"`.

## Build & run

```bash
cmake -S bench -B bench/build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build bench/build
./bench/build/bin/bench_rx        # …or bench_tx, bench_json, bench_dht, …
./bench/build/bin/bench_transport # two live Nodes on loopback; takes ~1 min
./bench/build/bin/bench_transport --serve            # …or the same suite between
./bench/build/bin/bench_transport --connect HOST:PORT #   two hosts, over a real path
```

Benchmarks are always compiled `-O3 -DNDEBUG`, whatever the parent tree is
configured as, and librats sources are compiled *into* each binary rather than
linked from the main build — so the code under test is optimized identically to
whatever it is being compared against.

`-DBENCH_FETCH_REFS=OFF` configures without a network. Three suites want a
third-party reference, all fetched at configure time and all optional: the JSON
suites take nlohmann/RapidJSON (whichever the build finds becomes an extra column)
and `bench_crypto` takes noise-c (without it that suite is skipped, with a warning
naming `-DBENCH_NOISEC_DIR=/path/to/noise-c` if you already have a checkout).
Everything else has no third-party dependency and builds straight from a compiler
if you prefer:

```bash
g++ -std=c++17 -O3 -DNDEBUG -Isrc -Ibench \
    bench/suites/bench_rx.cpp bench/baseline/legacy_buffers.cpp \
    bench/framework/alloc_track.cpp \
    src/librats/core/receive_buffer.cpp src/librats/wire/frame.cpp -o bench_rx   # + -lws2_32 on Windows
```

## The harness — `framework/bench.h`

Header-only, zero dependencies. Drop it into any C++17 project.

```cpp
#include "framework/bench.h"

int main() {
    bench::Bench b("My benchmarks");

    b.group("hash 1 KiB");
    b.bytes(1024);                       // enables a MB/s column for the group
    b.run("std::hash", []{ /* ... */ });
    b.run("mine",      []{ /* ... */ });

    b.report();                          // also runs automatically on destruction
}
```

* **Honest timing** — auto-calibrates iteration counts to a wall-time target, warms
  caches/branch-predictor, runs several rounds and reports the **median** (robust to
  OS jitter) plus a spread indicator (`±%`).
* **No dead-code elimination** — `bench::do_not_optimize()` / `bench::clobber()`.
* **Comparison-first** — within a group each entry is ranked against the fastest
  (`1.00x ← best`, `2.4x`, …).
* **Pretty** — aligned columns, human units (ns/µs/ms, K/M/G ops, MB/s), ANSI colour
  when stdout is a TTY.

Tuning: `b.config().min_time = 0.5; b.config().rounds = 9;`
Per-run throughput: `b.run("x", fn).set_bytes(n).set_items(n);`

## The JSON suites

`bench_json` measures `librats::Json` against `nlohmann::json`, RapidJSON, and its
own previous implementation (`baseline/stable_json`) across parse / serialize /
build / access hot paths. Datasets live in `support/json_data.h` and cover librats'
real traffic (peers, config, float/string blobs) plus general shapes — integer
arrays, long escape-free strings, wide objects, deep nesting.

`bench_complex` runs one deliberately nasty document — deep nesting, large arrays,
every scalar kind, escape-heavy strings, wide objects — end to end.

`bench_mem` reports the **resident heap a parsed DOM holds** and the **number of
allocations** it took to build. It is a separate executable on purpose: the
allocation instrumentation would otherwise add per-allocation overhead to
`bench_json`'s timings and unfairly penalise allocation-heavy DOMs. It carries its
own `operator new` override (predating `framework/alloc_track.h` — it also has to
tag RapidJSON's custom allocator), and links the C++ runtime statically so that
override is the only one in the program.

## The I/O suites — `bench_rx`, `bench_tx`

These measure the connection's receive and send paths against the implementation
they replaced in commit `5d64343` ("optimized receive_buffer + chained_send_buffer").

**What is actually under test.** Not the buffers in isolation — a buffer is only as
good as the loop driving it. Each suite reproduces the *real* read/write loops of
both commits (`Connection::on_readable`/`flush`, `PeerConnection::do_read`/`flush`)
verbatim, so what gets compared is the whole path.

Three things are instrumented:

* **syscalls** — the socket is mocked (`support/net_mock.h`), so `recv()` / `send()`
  / `sendmsg()` call counts and the number of iovec entries handed to the kernel are
  exact and repeatable. `RxKernel` hands back `min(len, queued)` and returns
  `EWOULDBLOCK` when dry, so a short read means what it means on a real socket;
  `TxKernel` accepts at most `per_call` bytes (≈`SO_SNDBUF`) and at most `budget`
  bytes before blocking (a congested peer).
* **memory** — `framework/alloc_track.cpp` overrides the global `operator
  new`/`delete` and counts allocations, total churn and peak residency. The block
  size on free comes from the allocator (`_msize` / `malloc_usable_size`), *not* from
  a prepended header, so no allocation changes size class because of the
  instrumentation.
* **time** — reported twice. **`userland`** is measured with the syscall mocked down
  to a memcpy: the naked cost of the buffer machinery. **`modelled`** adds
  `calls × 1 µs` back, a realistic syscall. Reading the two together is the point: a
  buffer that does more userland work in order to make fewer syscalls only wins in
  the second column.

`bench_rx` also prints a **decay timeline** — capacity and watermark of both buffers
as a peer sends one big message and then falls silent. The old buffer is a flat line.

`bench_tx` carries a third column, **`new+cork`**: queue a batch of messages and
flush *once*, the way libtorrent's `cork` does. It is **not** in the library — every
`send_*()` flushes immediately — and the column exists to show what the gather
machinery is still leaving on the table.

## The poller suite — `bench_poller`

`bench_rx` and `bench_tx` measure what happens *after* the poller says a socket is
ready. This one measures the saying: how many times `src/librats/core/io_poller.cpp` has to
wake the reactor to deliver one application message, and what each of those wakeups
costs as the registered set grows. Nothing is mocked — real loopback sockets, the
real poller, driven exactly the way `Reactor::run()` drives it (one blocking
`wait()`, read the socket dry, then keep asking with a zero timeout). A readiness
notification is not something you can mock and still be measuring it.

| experiment | what it isolates |
|---|---|
| `reports`  | readiness notifications spent per message, stream and datagram. **1.00 is the floor** |
| `recovery` | the same datagram socket before and after an unreachable destination |
| `scale`    | cost per event with N sockets registered, and what a listen socket adds |

The headline number is a ratio, not a duration, and it is the one to read first.
Every backend can deliver a message in one notification, but a completion-port
design has to work for it: arming the next overlapped receive while the data that
triggered the last one is still unread makes that receive complete on the spot, and
the caller comes back to an empty socket. That was the measured state of this code
— exactly **2.00** reports per message, half of them finding nothing — and it
doubled wakeups *and* reads across the whole receive path.

The two `recovery` rows must stay **equal**. On Windows an ICMP Port Unreachable
for an earlier send is delivered to the next receive as an error, the arm that
follows fails with it, and the poller hands the socket to its WSAPoll fallback so
that it cannot be left holding nothing — correct, but a hop slower (measured at
1.4x per datagram), and nothing else would ever move it back: `modify()` is the
only other promotion path and the reactor never calls it on the mux socket. A gap
between those rows means one transient ICMP packet now pins the busiest socket in
the process to the slow path for the rest of its life.

`scale` is flat in the number of *idle* sockets, as it should be — the interesting
row is `1 socket + a listener`, currently **1.4x**. A listen socket cannot carry
overlapped I/O, so on Windows it lives in a second mechanism that is polled on
every `wait()`; every server node pays that on every iteration of its reactor loop,
whether or not anything is connecting.

Loopback delivery is immediate, so these figures isolate the poller's own cost and
nothing else. A real network adds latency to the wait, not to the work measured
here — which is exactly why a wasted wakeup shows up so clearly.

## The DHT suite — `bench_dht`

librats' keyspace primitives (`src/librats/dht/id.h`) against the equivalent libtorrent
algorithms. Real libtorrent can't be linked here (`reference/` drags in Boost.Asio
and the whole session machinery), so the reference side is a standalone re-port of
`reference/kademlia/node_id.cpp` + `sha1_hash.hpp`, kept in libtorrent's *native*
representation (a 160-bit id as 5×uint32) so the comparison isn't rigged. It brings
its own timing loop rather than using `framework/bench.h`.

## The transport suite — `bench_transport`

The odd one out here, deliberately. Every other suite measures a **component**
against the implementation it replaced; this one measures a **path**: the same
encrypted protocol carried by the kernel's TCP stack and by the library's own
reliability layer over datagrams (`src/librats/transport/udp_stream.*`, `udp_mux.*`).
Nothing is mocked — two real `librats::Node`s in one process, real loopback
sockets, a real Noise_XX handshake, one reactor thread each.

Because the subject is the whole path, this is also the only target that **links
librats built as a subproject** instead of compiling a hand-listed set of sources
(`add_subdirectory` with tests/client/examples/bindings/install forced off). The
"optimized identically" rule still holds: `add_compile_options(-O3 -DNDEBUG)` is
issued before the subdirectory is added, so the library is built with the suite's
flags whatever the parent tree is configured as. `-DBENCH_TRANSPORT=OFF` skips it
if you only want the micro-suites.

The question it answers is not "is our UDP faster than TCP" — on loopback that
comparison is rigged, because a user-space stack skips no kernel work there. It
is **what moving reliability into user space costs, and where the two wires stop
being interchangeable**. `Link` (`src/librats/transport/link.h`) promises a peer over
either wire is indistinguishable to every layer above; these experiments are
picked to find where that promise is thin.

| experiment | what it isolates |
|---|---|
| `dial`     | round trips before the first application byte: TCP connect + Noise_XX vs Syn/Ack + Noise_XX |
| `rtt`      | serial request/response — the shape most likely to put `UdpStream::kDelayedAck` (20 ms) on the critical path |
| `bulk`     | steady-state throughput and, more usefully, **CPU-seconds per gigabyte** |
| `small`    | per-message rather than per-byte costs |
| `idle`     | N connected peers doing nothing — the price of `UdpMux::kTickInterval` sweeping every stream every 20 ms, plus resident bytes per peer |
| `burst`    | the largest *unpaced* application burst each wire survives before `CloseReason::SlowConsumer` |
| `fallback` | what the Happy-Eyeballs race in `node/dialer.h` costs against a TCP-only peer, cold and on a re-dial |

Three of these exist mainly because they can fail:

* **`burst`** — on TCP the burst lands in the kernel's send buffer; on the
  datagram side there is no such buffer, so `UdpStream::kSendQueueLimit` (2 MiB)
  is all that absorbs it and the rest piles into the connection's queue until it
  crosses `Connection::kDefaultSendHighWater` (8 MiB). Identical application code
  can therefore survive on one wire and lose its peer on the other, with no
  writable/backpressure callback through which it could have known. The row
  reports where that line sits.
* **`small`** — the large gap this shows is *not* the datagram stack being fast,
  and it is *not* Nagle either. Setting `TCP_NODELAY` makes this row **3.2x
  worse**, measured; the kernel's segment counter shows Nagle is currently the
  only thing coalescing small frames (200 k messages in 14'284 segments with it
  on, 264'340 with it off), and `strace` counts one `sendmsg` per frame in both
  builds. The real cost is that `Connection::send()` flushes write-through, so
  every frame makes its own trip into the kernel on either wire — the datagram
  side only partly escapes it, by topping up the tail packet in
  `UdpStream::write()` and batching `kUdpBatchMax` datagrams per syscall.
  Deferring the flush to the end of a reactor turn brings the two wires to
  ~1.1–1.3x of each other. Read it together with `rtt`, which has one frame in
  flight and so can show none of this.
* **`fallback`** — `identify` already tells a node which transports a peer
  accepts. A re-dial that costs the same as a cold one means that knowledge never
  reaches the dial.

**Reading the numbers.** CPU is whole-process: both nodes live in the benchmark,
so a figure covers sender *and* receiver — the honest number for a P2P node,
which is usually both. Loopback has no loss, no reordering and a near-zero RTT,
so congestion control, retransmission and the selective-ack path are all measured
at their cheapest: **every UDP figure is a floor on cost, not a ceiling.**

### The same suite over a real path

Loopback is the only way to get a controlled A/B of two transports, and it is
also the one path on which most of what the datagram stack exists for is
invisible: no propagation delay for an ack to hide behind, no MTU, no loss for
the SACK path to repair, no reordering, no middlebox. Slow start never ends and
the RTO never fires.

So the same binary is also the remote end of itself. Run it on the far host and
measure from the near one:

```bash
# on the remote host — stays up, prints the port to dial
./bench/build/bin/bench_transport --serve [--port 9977] [--transport tcp|udp|both]

# on this host — measures, prints the same tables, exits
./bench/build/bin/bench_transport --connect HOST:PORT [--bulk-mb 64] [--rtt 500]
```

Both ends must pass the same `--protocol` (it is bound into the Noise handshake,
so a mismatch cannot complete one at all), and the responder must be reachable on
that port over every wire being measured — a wire that never comes up is reported
as such and the table drops to one column instead of comparing against zeros.
`--help` lists the sizing flags (`--frame-kb`, `--credit-kb`, `--small`,
`--small-credit`, `--rtt-bytes`, `--dials`, `--bind`).

| experiment | what changes when the path is real |
|---|---|
| `dial`     | counts **round trips**, not node setup. The note under `bench_dial()` stops being theoretical here: folding the initiator's first Noise message into the Syn is worth one whole RTT of every dial |
| `rtt`      | `min` is the path, `median − min` is what this stack adds, and `p99` is queueing — a p99 ~20 ms above the median is `UdpStream::kDelayedAck` on the critical path |
| `bulk`     | **both directions**, because real links are asymmetric: upload (we send) and download (the remote pushes on request), each with its own CPU-per-GB |
| `small`    | per-message cost where a per-packet round trip is not free |

Both ends run the same four channels: `echo` (returned verbatim), `data`, `ack`
(cumulative `[u64 bytes][u64 msgs]` from whoever is receiving `data`), and `ctl`
(`flush`, `push <bytes> <frame> <credit>`). The acks do two jobs at once — they
pace the sender, so neither wire is ever measured while it is being dropped as a
slow consumer (see `burst` above), and they are how the sender knows the bytes
*landed* rather than merely left. Channels share one ordered stream, so a `flush`
sent after the last data frame is delivered after it and the closing ack is exact.

Two things to keep in mind reading a remote run. CPU is still whole-process, but
here a process is **one** node, so the per-gigabyte figures are per-node and the
upload (sender) and download (receiver) rows are directly comparable. And on a
very fast path both wires carry an extra artifact: the ack stream is small
messages, and every frame currently costs its own write (see `small` above), so
a narrow credit window paces the sender late — `--credit-kb` is the runway that
absorbs it, and on any link whose bandwidth-delay product fits inside the credit
window it does not arise.

Loss behaviour on a *synthetic* lossy path (`netem`) is still out of scope; this
mode measures whatever loss the real path actually has.

## The crypto suite — `bench_crypto`

librats' Noise primitives against the **noise-c** reference they were ported from
(fetched at configure time, or `-DBENCH_NOISEC_DIR=...`): SHA-256/512, BLAKE2b/2s, ChaCha20, Poly1305, the ChaCha20-Poly1305
AEAD seal, and X25519 scalar multiplication (the Noise_XX handshake hot path — four
per side). Both sides are compiled from source at `-O3` into one binary and ranked
head-to-head over 8 KiB payloads.

The reference cannot link as-is — librats kept the upstream function names verbatim
on copy — so each `baseline/noisec_*.c` shim `#define`-renames the upstream public
symbols behind an `nc_*`/`ncref_*` prefix before `#include`-ing the reference `.c`
(as `<src/crypto/...>`, resolved against whatever noise-c root is on the include
path), exposing only the small one-shot API in `baseline/noisec.h`. Nothing of
noise-c is *built* — only those few `.c` files are pulled in. For the byte-primitives
the two sides are the *same source*, so **matching numbers (≈1.00×) are the expected,
correct result** — the suite exists to prove the port introduced no regression, and
to catch one if a future edit diverges. The AEAD group pits librats' own `chachapoly`
glue against the identical RFC 8439 construction over the reference primitives.

Because these are C sources, the bench project enables the C language
(`project(librats_bench C CXX)`); the other suites are C++ only.
