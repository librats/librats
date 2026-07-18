/* noise-c ChaCha20-Poly1305 AEAD reference, symbol-isolated. See noisec.h.
 *
 * noise-c's real AEAD (backend/ref/cipher-chachapoly.c) is bound to the
 * NoiseCipherState object and its internal header tree, so we compose the same
 * RFC 8439 construction directly from the reference chacha + poly1305 primitives.
 * The steps mirror librats' chachapoly_encrypt byte-for-byte, so this isolates
 * the cost difference (if any) between librats' AEAD glue and the reference
 * primitives it is built on. */
#define chacha_keysetup      ncaead_chacha_keysetup
#define chacha_ivsetup       ncaead_chacha_ivsetup
#define chacha_encrypt_bytes ncaead_chacha_encrypt_bytes
#include "../../reference2/src/crypto/chacha/chacha.c"

#define poly1305_init   ncaead_poly1305_init
#define poly1305_update ncaead_poly1305_update
#define poly1305_finish ncaead_poly1305_finish
#define poly1305_auth   ncaead_poly1305_auth
#define poly1305_verify ncaead_poly1305_verify
#define poly1305_power_on_self_test ncaead_poly1305_power_on_self_test
#include "../../reference2/src/crypto/donna/poly1305-donna.c"

#include "noisec.h"
#include <string.h>

static void nc_write_le64(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}
static void nc_pad16(poly1305_context* ctx, size_t data_len) {
    static const uint8_t zeros[16] = {0};
    size_t pad = (16 - (data_len % 16)) % 16;
    if (pad) ncaead_poly1305_update(ctx, zeros, pad);
}

size_t nc_chachapoly_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                             const uint8_t* ad, size_t ad_len,
                             const uint8_t* pt, size_t pt_len, uint8_t* out) {
    chacha_ctx chacha;
    poly1305_context poly;
    uint8_t poly_key[64];
    uint8_t block0[8] = {0};
    uint8_t block1[8] = {1, 0, 0, 0, 0, 0, 0, 0};
    uint8_t len_block[16];

    ncaead_chacha_keysetup(&chacha, key, 256);
    ncaead_chacha_ivsetup(&chacha, nonce + 4, block0);
    memset(poly_key, 0, 64);
    ncaead_chacha_encrypt_bytes(&chacha, poly_key, poly_key, 64);

    ncaead_chacha_keysetup(&chacha, key, 256);
    ncaead_chacha_ivsetup(&chacha, nonce + 4, block1);
    if (pt_len) ncaead_chacha_encrypt_bytes(&chacha, pt, out, (uint32_t)pt_len);

    ncaead_poly1305_init(&poly, poly_key);
    if (ad_len) { ncaead_poly1305_update(&poly, ad, ad_len); nc_pad16(&poly, ad_len); }
    if (pt_len) { ncaead_poly1305_update(&poly, out, pt_len); nc_pad16(&poly, pt_len); }
    nc_write_le64(len_block, ad_len);
    nc_write_le64(len_block + 8, pt_len);
    ncaead_poly1305_update(&poly, len_block, 16);
    ncaead_poly1305_finish(&poly, out + pt_len);
    return pt_len + 16;
}
