# librats Python Bindings — Technical Notes

Technical details of the Python bindings, which target the librats C ABI
(`src/bindings/rats.h`) via `ctypes`.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Python Application                       │
├─────────────────────────────────────────────────────────────┤
│                      librats_py package                      │
│  core.py (RatsClient)   exceptions.py   enums.py             │
│  callbacks.py (CFUNCTYPE prototypes + Pythonic aliases)      │
│  ctypes_wrapper.py (CDLL + argtypes/restypes, RatsConfig)    │
├─────────────────────────────────────────────────────────────┤
│         librats shared library — C ABI: src/bindings/rats.h  │
│              (rats.dll / librats.so / librats.dylib)         │
└─────────────────────────────────────────────────────────────┘
```

## Module structure

| File | Role |
| --- | --- |
| `core.py` | `RatsClient` — the high-level node wrapper |
| `ctypes_wrapper.py` | `CDLL` load, `RatsConfig` struct, all argtypes/restypes, `take_string` helper |
| `callbacks.py` | Raw `CFUNCTYPE` prototypes mirroring `rats.h` + Pythonic type aliases |
| `enums.py` | `RatsError`/`Security`/`LogLevel`/`FileTransferStatus`, `VersionInfo` |
| `exceptions.py` | Exception hierarchy + `check_error` |
| `examples/`, `tests/` | Demos and tests |

## The C ABI contract that shapes the bindings

* **Opaque handle.** `rats_t` is a `void*`; declared `c_void_p`. Constructed via
  `rats_create_config(&cfg)` from a `rats_config_t` obtained from
  `rats_config_default()` (see `RatsConfig` in `ctypes_wrapper.py`). The struct
  must start from the defaults — zero-initialising it would yield a dial-only
  node.
* **Error model.** Fallible calls return `rats_error_t` (`RATS_OK == 0`). The
  bindings route non-OK codes through `check_error`, which raises the matching
  exception. This inverts the old "non-zero == success" convention.
* **Heap vs static strings.** `rats_local_id`, `rats_protocol_name`,
  `rats_protocol_version` and each entry of `rats_peer_ids` are heap-allocated
  and must be freed with `rats_string_free`. They are declared `c_void_p` (NOT
  `c_char_p`, which auto-converts and would leak/lose the pointer) and read via
  `take_string`, which copies the bytes then frees the original.
  `rats_version_string`, `rats_git_describe`, `rats_error_str` return static
  strings declared `c_char_p` — never freed.
* **Peer id arrays.** `rats_peer_ids(node, &count)` returns `char**`; declared
  `POINTER(c_void_p)`. Each element is copied out, then the whole array is freed
  with `rats_free_peer_ids(arr, count)`.

## Callback bridging

The raw `CFUNCTYPE` prototypes in `callbacks.py` mirror the C typedefs exactly.
Each C callback takes `void* user` first. Payloads arrive as a `void*`
(`c_void_p`) + `size_t` length pair; ids/topics/JSON arrive as `c_char_p`.

`core.py` wraps each user callback in a *trampoline* that:

1. decodes `c_char_p` ids/topics to `str`,
2. copies payload bytes via `string_at(ptr, length)` into a Python `bytes`,
3. parses JSON for the typed-JSON path,
4. **catches every exception** (`_report`) so nothing propagates into C.

```python
def trampoline(user, peer_id_ptr, data_ptr, length):
    try:
        peer_id = peer_id_ptr.decode('utf-8') if peer_id_ptr else ""
        data = string_at(data_ptr, length) if (data_ptr and length) else b""
        callback(peer_id, data)
    except Exception as exc:
        _report(exc, "message callback")
c_cb = MessageCallbackType(trampoline)
self._c_callbacks["on:chat"] = c_cb   # keep the CFUNCTYPE object alive
```

### Keeping callbacks alive

Every `CFUNCTYPE` object is stored in `RatsClient._c_callbacks` for the node's
lifetime. If a wrapper were garbage-collected while C still held the pointer,
the next invocation on the reactor thread would crash. JSON `on_json` handlers
are additive, so each registration uses a unique key (`json:<type>:<id>`);
`off_json(type)` drops all retained trampolines for that type.

### Threading

Callbacks run on the librats internal reactor thread. The GIL serialises Python
execution, but user callbacks should not block — they stall the reactor.

## Lifecycle ordering

Register callbacks and call `enable_*` **before** `start()`:

* `enable_*` after `start()` → `RATS_ERR_ALREADY_STARTED` → `RatsAlreadyStartedError`.
* subsystem op before its `enable_*` → `RATS_ERR_NOT_ENABLED` → `RatsNotEnabledError`.

`set_max_peers` / `add_reconnect` / `remove_reconnect` may be called before or
after start.

## Error / exception mapping

```
RatsError (base, error_code = rats_error_t)
├── RatsInvalidArgError       (INVALID_ARG)
├── RatsNotStartedError       (NOT_STARTED)
├── RatsAlreadyStartedError   (ALREADY_STARTED)
├── RatsNotEnabledError       (NOT_ENABLED)
├── RatsNoSuchPeerError       (NO_SUCH_PEER)
├── RatsBindError             (BIND)
└── RatsConnectionError       (connection helpers)
```

`send_file` / `send_directory` return a `uint64` transfer id (0 = failure);
the wrappers raise `RatsError` on a 0 id rather than returning it.

## Library loading

`find_librats_library()` searches: alongside the package, `.`,
`../../build/{lib,bin}`, `../build`, `../../build`, `../../../build`,
`/usr/local/lib`, `/usr/lib`, then `LD_LIBRARY_PATH` / `PATH`, then the bare
name via the OS loader. Names: `rats.dll`/`librats.dll`, `librats.dylib`,
`librats.so`/`librats.so.1`.

## Building the native library

`build.py --build-native` runs CMake with `-DRATS_SHARED_LIBRARY=ON`
(tests/examples off), then copies the shared library next to the package. CMake
compiles the full `LIBRARY_SOURCES` set, including `src/bindings/rats.cpp` (gated
by `RATS_BINDINGS`, default ON), and links `ws2_32`/`iphlpapi`/`bcrypt` on
Windows and `pthread` elsewhere — include paths `src/`, `src/crypto/`, and the
generated `version.h` directory.

`build.py --compile-direct` prints a CMake-free recipe that mirrors
`LIBRARY_SOURCES` for environments without CMake. The canonical source list
lives in `CMakeLists.txt`; keep `build.py`'s `LIBRARY_SOURCES` in sync.

## Tests

```bash
python -m pytest librats_py/tests/test_client.py        # unit (skips if no lib)
python -m pytest librats_py/tests/test_integration.py   # needs native library
```

## Adding a new C function

1. Declare it in `ctypes_wrapper.py` (`argtypes` / `restype`, matching
   `rats.h`; use `c_void_p` for heap strings, `c_char_p` for static ones).
2. Add a method in `core.py`, routing the result through `check_error` for
   `rats_error_t` returns and `take_string` for heap strings.
3. For a new callback, add the `CFUNCTYPE` prototype + Pythonic alias in
   `callbacks.py` and a trampoline that keeps the object alive in
   `_c_callbacks`.

## Removed features

ICE/STUN/TURN, encryption enable/keys, configuration load/save, granular logging
(colours/timestamps/rotation/retention/console), historical peers, statistics
JSON (connection/gossipsub/file-transfer) and automatic-discovery toggles are
not part of the new C ABI and have no Python surface. See the README migration
table for replacements (`enable_port_mapping`, the `security`/`data_dir`
constructor args, `enable_dht`/`enable_mdns`, `enable_reconnect`).
