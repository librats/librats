# bench — a tiny micro-benchmark harness

`bench.h` is a header-only, dependency-free benchmark harness. Drop it into any
C++17 project to measure and **compare** competing implementations with honest
numbers and a readable, colourised report.

## Why another one

* **Honest timing** — auto-calibrates iteration counts to a wall-time target,
  warms caches/branch-predictor, runs several rounds and reports the **median**
  (robust to OS jitter) plus a spread indicator (`±%`).
* **No dead-code elimination** — `bench::do_not_optimize()` / `bench::clobber()`
  stop the optimizer from deleting the work under test.
* **Comparison-first** — benchmarks are grouped; within a group each entry is
  ranked against the fastest (`1.00x ← best`, `2.4x`, …).
* **Pretty** — aligned columns, human units (ns/µs/ms, K/M/G ops, MB/s), ANSI
  colour when stdout is a TTY (auto-enabled on Windows 10+).

## Use it

```cpp
#include "bench.h"

int main() {
    bench::Bench b("My benchmarks");

    b.group("hash 1 KiB");
    b.bytes(1024);                       // enables a MB/s column for the group
    b.run("std::hash", []{ /* ... */ });
    b.run("mine",      []{ /* ... */ });

    b.report();                          // also runs automatically on destruction
}
```

Tuning: `b.config().min_time = 0.5; b.config().rounds = 9;`
Annotate throughput per run: `b.run("x", fn).set_bytes(n).set_items(n);`

## The JSON benchmark

`bench_json.cpp` benchmarks `librats::Json` against `nlohmann::json` and
RapidJSON across parse / serialize / build / access hot paths. The reference
libraries are fetched at configure time and are optional — whichever the build
finds are included as extra columns.

```bash
cmake -S bench -B bench/build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build bench/build
./bench/build/bin/bench_json
```

`librats/src/util/json.cpp` is compiled directly into the benchmark with `-O3`,
so the code under test is optimized identically to the reference libraries
(independent of how the main library tree was configured).
