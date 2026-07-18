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
│   ├── bench_dht.cpp     keyspace primitives vs libtorrent's
│   └── bench_crypto.cpp  Noise primitives vs the noise-c reference
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
```

Benchmarks are always compiled `-O3 -DNDEBUG`, whatever the parent tree is
configured as, and librats sources are compiled *into* each binary rather than
linked from the main build — so the code under test is optimized identically to
whatever it is being compared against.

`-DBENCH_FETCH_REFS=OFF` configures without a network. Only the JSON suites need
nlohmann/RapidJSON (fetched at configure time, optional — whichever the build finds
becomes an extra column); everything else has no third-party dependency and builds
straight from a compiler if you prefer:

```bash
g++ -std=c++17 -O3 -DNDEBUG -Isrc -Ibench \
    bench/suites/bench_rx.cpp bench/baseline/legacy_buffers.cpp \
    bench/framework/alloc_track.cpp \
    src/core/receive_buffer.cpp src/wire/frame.cpp -o bench_rx   # + -lws2_32 on Windows
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

## The DHT suite — `bench_dht`

librats' keyspace primitives (`src/dht/id.h`) against the equivalent libtorrent
algorithms. Real libtorrent can't be linked here (`reference/` drags in Boost.Asio
and the whole session machinery), so the reference side is a standalone re-port of
`reference/kademlia/node_id.cpp` + `sha1_hash.hpp`, kept in libtorrent's *native*
representation (a 160-bit id as 5×uint32) so the comparison isn't rigged. It brings
its own timing loop rather than using `framework/bench.h`.

## The crypto suite — `bench_crypto`

librats' Noise primitives against the **noise-c** reference (`reference2/`) they
were ported from: SHA-256/512, BLAKE2b/2s, ChaCha20, Poly1305, the ChaCha20-Poly1305
AEAD seal, and X25519 scalar multiplication (the Noise_XX handshake hot path — four
per side). Both sides are compiled from source at `-O3` into one binary and ranked
head-to-head over 8 KiB payloads.

The reference cannot link as-is — librats kept the upstream function names verbatim
on copy — so each `baseline/noisec_*.c` shim `#define`-renames the upstream public
symbols behind an `nc_*`/`ncref_*` prefix before `#include`-ing the reference `.c`,
exposing only the small one-shot API in `baseline/noisec.h`. For the byte-primitives
the two sides are the *same source*, so **matching numbers (≈1.00×) are the expected,
correct result** — the suite exists to prove the port introduced no regression, and
to catch one if a future edit diverges. The AEAD group pits librats' own `chachapoly`
glue against the identical RFC 8439 construction over the reference primitives.

Because these are C sources, the bench project enables the C language
(`project(librats_bench C CXX)`); the other suites are C++ only.
