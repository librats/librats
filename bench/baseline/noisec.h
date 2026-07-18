#pragma once
// ─────────────────────────────────────────────────────────────────────────────
//  noisec.h — one-shot C entry points into the *noise-c* reference primitives
//  (reference2/), used by suites/bench_crypto.cpp to measure librats' crypto
//  against the upstream code it was ported from.
//
//  librats kept the upstream function names verbatim on copy, so the reference
//  .c files cannot be linked next to librats' as-is. Each noisec_*.c shim
//  #defines the upstream public symbols to an `ncref_`/`ncaead_` prefix before
//  #including the reference .c, then exposes the small `nc_*` API declared here.
//  Only these `nc_*` symbols are visible to the benchmark.
// ─────────────────────────────────────────────────────────────────────────────
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void   nc_sha256(uint8_t out[32], const void* data, size_t len);
void   nc_sha512(uint8_t out[64], const void* data, size_t len);
void   nc_blake2b(uint8_t out[64], const void* data, size_t len);
void   nc_blake2s(uint8_t out[32], const void* data, size_t len);
// Raw ChaCha20 keystream/XOR over `len` bytes (key=256-bit, 8-byte iv, 8-byte counter).
void   nc_chacha20(uint8_t* out, const uint8_t* in, size_t len,
                   const uint8_t key[32], const uint8_t iv[8], const uint8_t counter[8]);
void   nc_poly1305(uint8_t mac[16], const void* m, size_t len, const uint8_t key[32]);
int    nc_curve25519(uint8_t out[32], const uint8_t secret[32], const uint8_t basepoint[32]);
// ChaCha20-Poly1305 AEAD (RFC 8439, Noise nonce layout) built from the reference
// chacha + poly1305 — mirrors librats' chachapoly_encrypt construction exactly.
size_t nc_chachapoly_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                             const uint8_t* ad, size_t ad_len,
                             const uint8_t* pt, size_t pt_len, uint8_t* out);

#ifdef __cplusplus
}
#endif
