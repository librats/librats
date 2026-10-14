# librats Python bindings — maintainer notes

How the package is put together, for whoever changes it. Usage is in
[README.md](README.md).

## Layout

| File | Role |
| --- | --- |
| `ctypes_wrapper.py` | loads the library; ctypes mirrors of every `rats.h` struct; one `_SIGNATURES` table with the restype/argtypes of every function |
| `callbacks.py` | `CFUNCTYPE` prototypes matching the C callback typedefs, and the Pythonic callback signatures |
| `enums.py` | the C enums as `IntEnum`/`IntFlag`, the limits, and the value types (`PeerInfo`, `PathStats`, `FileProgress`, `VersionInfo`) |
| `exceptions.py` | one `RatsError` subclass per `rats_error_t`; `check_error()` raises the right one |
| `core.py` | `RatsNode` and the process-wide functions |

## Rules the C ABI imposes

- **Structs must match byte for byte.** Field order and widths in
  `ctypes_wrapper.py` follow `rats.h` exactly (`size_t` → `c_size_t`, enums →
  `c_int`, `char[64]` → `c_char * 64`). `rats_config_t` and `rats_bt_config_t`
  are zero-initialisable, which is why `RatsNode` builds a fresh `RatsConfig()`
  and only sets what the caller passed; booleans that default to on are spelled
  `disable_*` in C and inverted in `core.py`.
- **Strings.** `rats_local_id`, `rats_protocol` and the static names are
  library-owned `const char*`, declared `c_char_p` (ctypes copies them; nothing
  is freed). `rats_peer_ids` / `rats_observed_addresses` return a caller-owned
  `char**`, declared `POINTER(c_char_p)` and released with `rats_strings_free`
  after copying.
- **The handle is not checked by C.** Every method reaches it through
  `RatsNode._h`, which raises once the node is destroyed instead of passing NULL
  on.
- **`rats_create` returns NULL for an impossible config** (no transport, a
  preferred transport that is off, an out-of-range enum) or an identity it
  cannot load; the constructor turns that into `RatsInvalidArgError`.

## Callbacks

Each user callback is wrapped by `_guard()` in `core.py`, which converts the C
arguments (`c_char_p` → `str`, `void*` + length → `bytes`, struct pointers →
dataclasses via `Structure.from_address`) and catches every exception, so
nothing unwinds into C.

Every `CFUNCTYPE` object is appended to `RatsNode._thunks` and kept until the
node is gone. That includes handlers later replaced (`subscribe` again,
`on_file_offer` again) or removed (`off_json`, `unsubscribe`): the C side may be
calling one on a reactor thread at that moment, and a collected thunk is a
crash, while a kept one costs a few hundred bytes.

ctypes releases the GIL during a foreign call, so a reactor thread can enter a
Python callback while the main thread is inside, say, `destroy()`, which joins
those threads.

## Adding a C function

1. Add its `(name, restype, argtypes)` to `_SIGNATURES` and any new struct to
   `ctypes_wrapper.py`; a new callback typedef gets a prototype in
   `callbacks.py`.
2. Add the method to `RatsNode`, routing a `rats_error_t` through
   `check_error()`, and a test under `librats_py/tests` (mark it `native`).
3. Check the layout against the compiler when a struct changes: compile a small
   C file printing `sizeof`/`offsetof` and compare with ctypes `sizeof` and
   `Field.offset`.

## Testing against a local build

```bash
cmake -S .. -B ../build-shared -DRATS_SHARED_LIBRARY=ON -DRATS_STATIC_LIBRARY=OFF -DRATS_BUILD_TESTS=OFF
cmake --build ../build-shared
LIBRATS_LIBRARY_PATH=../build-shared/bin python -m pytest librats_py/tests
```

With MinGW, put the runtime DLLs next to `librats.dll` first (see README).
