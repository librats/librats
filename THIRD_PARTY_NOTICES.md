# Third-party notices

librats itself is licensed under the MIT license (see [LICENSE](LICENSE)).

It additionally embeds a small number of third-party cryptographic and platform
compatibility sources. They are not separate libraries that could be linked
against: they are single-primitive implementations that were taken into the tree
and adapted (renamed symbols, trimmed variants, export macros, MSVC fixes). Each
one keeps its original copyright notice in the file header, and the full license
text of each is reproduced under [`licenses/`](licenses/).

The effective license of a build is therefore:

```
MIT AND BSD-3-Clause AND BSD-2-Clause AND BSD-1-Clause
```

For every non-Android target the BSD-2-Clause and BSD-1-Clause parts are not
compiled, and the expression reduces to `MIT AND BSD-3-Clause`.

## Components

### curve25519-donna — BSD-3-Clause

* Upstream: <https://github.com/agl/curve25519-donna>
* Copyright 2008, Google Inc. — Adam Langley `<agl@imperialviolet.org>`,
  derived from public domain C code by Daniel J. Bernstein
* In tree: `src/crypto/curve25519.c`, `src/crypto/curve25519.h`
* License text: [`licenses/curve25519-donna.LICENSE`](licenses/curve25519-donna.LICENSE)
* Modifications: added the `RATS_API` export attribute to the exported
  `curve25519_basepoint` data symbol and to the public functions; MSVC `inline`
  shim; header guard renamed to `LIBRATS_CURVE25519_H`.
* Provides X25519 for the Noise_XX handshake.

### poly1305-donna — MIT (dual-licensed MIT / public domain upstream)

* Upstream: <https://github.com/floodyberry/poly1305-donna>
* Author: Andrew Moon (floodyberry)
* In tree: `src/crypto/poly1305.c`, `src/crypto/poly1305.h`
* License text: [`licenses/poly1305-donna.LICENSE`](licenses/poly1305-donna.LICENSE)
* Modifications: the 8/16/32/64-bit backend headers were folded into a single
  translation unit with automatic 32/64-bit selection; header guard renamed to
  `LIBRATS_POLY1305_H`.
* Provides the Poly1305 authenticator for ChaCha20-Poly1305.

### noise-c — MIT

* Upstream: <https://github.com/rweather/noise-c>
* Copyright (C) 2016 Southern Storm Software, Pty Ltd. (Rhys Weatherley)
* In tree: `src/crypto/chacha.{c,h}`, `src/crypto/sha256.{c,h}`,
  `src/crypto/sha512.{c,h}`, `src/crypto/blake2b.{c,h}`,
  `src/crypto/blake2s.{c,h}`, `src/crypto/blake2_endian.h`
* License text: [`licenses/noise-c.LICENSE`](licenses/noise-c.LICENSE)
* Modifications: near-verbatim. Header guards and configuration macros renamed
  to the `LIBRATS_*` / `CHACHA_*` prefix, `blake2-endian.h` renamed to
  `blake2_endian.h`, explicit narrowing casts added to silence MSVC warnings,
  a one-shot `sha256_hash()` convenience wrapper added, and the big-endian
  BLAKE2b message-load stride corrected.
* The BLAKE2b/BLAKE2s sources note that they in turn start from
  <https://github.com/rweather/arduinolibs>, by the same author under the same
  license.
* librats' Noise Protocol implementation (`src/crypto/noise.{h,cpp}`), the
  HKDF-SHA256 (`src/crypto/hkdf.{c,h}`) and ChaCha20-Poly1305 AEAD
  (`src/crypto/chachapoly.{c,h}`) layers on top are original librats code
  written against RFC 5869 / RFC 8439 and the Noise specification, and are
  MIT-licensed as part of librats.

### ifaddrs-android — BSD-2-Clause AND BSD-1-Clause

* Upstream: <https://github.com/kmackay/android-ifaddrs>
* Copyright (c) 2013, Kenneth MacKay (`ifaddrs-android.c`, BSD-2-Clause)
* Copyright (c) 1995, 1999 Berkeley Software Design, Inc. (`ifaddrs-android.h`,
  the BSDI `<ifaddrs.h>` interface, BSD-1-Clause)
* In tree: `3rdparty/android/ifaddrs-android.c`, `3rdparty/android/ifaddrs-android.h`
* License text: [`licenses/ifaddrs-android.LICENSE`](licenses/ifaddrs-android.LICENSE)
* Modifications: none of substance.
* **Compiled only when targeting Android API level < 24**, where bionic does not
  yet provide `getifaddrs()` (see the `ANDROID_API_LEVEL LESS 24` branch in
  `CMakeLists.txt`). It is absent from every other build.

## Original librats code

Everything else under `src/`, including `src/crypto/sha1.{h,cpp}`,
`src/crypto/crc32.{h,cpp}`, `src/crypto/hkdf.{c,h}`,
`src/crypto/chachapoly.{c,h}` and `src/crypto/noise.{h,cpp}`, is original
librats code under the MIT license.

Note that `install(DIRECTORY src/ ...)` installs the whole header tree, so the
third-party headers listed above are installed alongside librats' own headers
and their notices travel with them.
