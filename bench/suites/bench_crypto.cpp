// ─────────────────────────────────────────────────────────────────────────────
//  bench_crypto — librats crypto vs the noise-c reference it was ported from.
//
//  For each primitive the two implementations are compiled from source at -O3
//  into one binary (the reference side symbol-isolated behind `nc_*`, see
//  baseline/noisec.h) and ranked head-to-head. The ported byte-primitives
//  (SHA-2, BLAKE2, ChaCha20, Poly1305, Curve25519) are the *same source* on both
//  sides, so identical numbers are the expected, correct result — this suite
//  proves the port introduced no performance regression. The AEAD group compares
//  librats' own chachapoly glue against the equivalent construction over the
//  reference primitives.
// ─────────────────────────────────────────────────────────────────────────────
#include "framework/bench.h"
#include "baseline/noisec.h"

extern "C" {
#include "crypto/sha256.h"
#include "crypto/sha512.h"
#include "crypto/blake2b.h"
#include "crypto/blake2s.h"
#include "crypto/chacha.h"
#include "crypto/poly1305.h"
#include "crypto/curve25519.h"
#include "crypto/chachapoly.h"
}

#include <cstdint>
#include <cstring>
#include <vector>

using bench::do_not_optimize;

int main() {
    constexpr size_t N = 8192;  // payload for the bulk primitives
    std::vector<uint8_t> in(N), out(N + 16);
    for (size_t i = 0; i < N; i++) in[i] = (uint8_t)(i * 131 + 7);

    uint8_t key[32], nonce[12], iv[8], counter[8] = {0};
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i + 1);
    for (int i = 0; i < 12; i++) nonce[i] = 0;              // Noise nonce: zero counter
    for (int i = 0; i < 8; i++)  iv[i] = (uint8_t)(i + 100);

    uint8_t h32[32], h64[64], mac[16], pub[32];

    bench::Bench b("librats crypto vs noise-c reference (8 KiB payloads, -O3)");
    b.config().min_time = 0.6;
    b.config().rounds   = 9;

    // ── SHA-256 ──────────────────────────────────────────────────────────────
    b.group("SHA-256  (8 KiB)").bytes(N);
    b.run("librats", [&]{ sha256_hash(h32, in.data(), N); do_not_optimize(h32); });
    b.run("noise-c", [&]{ nc_sha256(h32, in.data(), N);   do_not_optimize(h32); });

    // ── SHA-512 ──────────────────────────────────────────────────────────────
    b.group("SHA-512  (8 KiB)").bytes(N);
    b.run("librats", [&]{ sha512_hash(h64, in.data(), N); do_not_optimize(h64); });
    b.run("noise-c", [&]{ nc_sha512(h64, in.data(), N);   do_not_optimize(h64); });

    // ── BLAKE2b ──────────────────────────────────────────────────────────────
    b.group("BLAKE2b  (8 KiB)").bytes(N);
    b.run("librats", [&]{ BLAKE2b_context_t c; BLAKE2b_reset(&c);
                          BLAKE2b_update(&c, in.data(), N); BLAKE2b_finish(&c, h64);
                          do_not_optimize(h64); });
    b.run("noise-c", [&]{ nc_blake2b(h64, in.data(), N); do_not_optimize(h64); });

    // ── BLAKE2s ──────────────────────────────────────────────────────────────
    b.group("BLAKE2s  (8 KiB)").bytes(N);
    b.run("librats", [&]{ BLAKE2s_context_t c; BLAKE2s_reset(&c);
                          BLAKE2s_update(&c, in.data(), N); BLAKE2s_finish(&c, h32);
                          do_not_optimize(h32); });
    b.run("noise-c", [&]{ nc_blake2s(h32, in.data(), N); do_not_optimize(h32); });

    // ── ChaCha20 keystream ───────────────────────────────────────────────────
    b.group("ChaCha20  (8 KiB)").bytes(N);
    b.run("librats", [&]{ chacha_ctx x; chacha_keysetup(&x, key, 256);
                          chacha_ivsetup(&x, iv, counter);
                          chacha_encrypt_bytes(&x, in.data(), out.data(), (uint32_t)N);
                          do_not_optimize(out[0]); });
    b.run("noise-c", [&]{ nc_chacha20(out.data(), in.data(), N, key, iv, counter);
                          do_not_optimize(out[0]); });

    // ── Poly1305 MAC ─────────────────────────────────────────────────────────
    b.group("Poly1305  (8 KiB)").bytes(N);
    b.run("librats", [&]{ poly1305_auth(mac, in.data(), N, key); do_not_optimize(mac); });
    b.run("noise-c", [&]{ nc_poly1305(mac, in.data(), N, key);   do_not_optimize(mac); });

    // ── ChaCha20-Poly1305 AEAD (seal) ────────────────────────────────────────
    b.group("ChaCha20-Poly1305 seal  (8 KiB)").bytes(N);
    b.run("librats", [&]{ chachapoly_encrypt(key, nonce, nullptr, 0, in.data(), N, out.data());
                          do_not_optimize(out[0]); });
    b.run("noise-c", [&]{ nc_chachapoly_encrypt(key, nonce, nullptr, 0, in.data(), N, out.data());
                          do_not_optimize(out[0]); });

    // ── X25519 scalar multiplication (the handshake hot path) ────────────────
    // Chain outputs so each op depends on the last — no throughput bytes, just
    // ops/s (a Noise_XX handshake performs 4 of these per side).
    uint8_t sk[32]; memcpy(sk, key, 32);
    b.group("X25519 scalarmult  (per op)").items(1);
    b.run("librats", [&]{ curve25519_donna(pub, sk, curve25519_basepoint);
                          sk[0] = pub[0]; do_not_optimize(pub); });
    b.run("noise-c", [&]{ nc_curve25519(pub, sk, curve25519_basepoint);
                          sk[0] = pub[0]; do_not_optimize(pub); });

    b.report();
    return 0;
}
