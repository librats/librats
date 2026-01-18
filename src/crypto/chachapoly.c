/*
 * ChaCha20-Poly1305 AEAD construction for Noise Protocol
 * Based on RFC 8439
 */

#include "chachapoly.h"
#include "chacha.h"
#include "poly1305.h"
#include <string.h>

/* Convert 64-bit nonce counter to 12-byte Noise nonce format */
static void make_nonce(uint8_t out[12], uint64_t n) {
    /* Noise protocol nonce format: 4 bytes zeros + 8 bytes little-endian counter */
    out[0] = 0;
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;
    out[4] = (uint8_t)(n);
    out[5] = (uint8_t)(n >> 8);
    out[6] = (uint8_t)(n >> 16);
    out[7] = (uint8_t)(n >> 24);
    out[8] = (uint8_t)(n >> 32);
    out[9] = (uint8_t)(n >> 40);
    out[10] = (uint8_t)(n >> 48);
    out[11] = (uint8_t)(n >> 56);
}

/* Write 64-bit value in little-endian */
static void write_le64(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32);
    p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48);
    p[7] = (uint8_t)(v >> 56);
}

/* Constant-time comparison */
static int secure_compare(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

/* Zero memory securely */
static void secure_zero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

/* Pad to 16-byte boundary for Poly1305 */
static void poly1305_pad16(poly1305_context *ctx, size_t data_len) {
    static const uint8_t zeros[16] = {0};
    size_t pad = (16 - (data_len % 16)) % 16;
    if (pad > 0) {
        poly1305_update(ctx, zeros, pad);
    }
}

size_t chachapoly_encrypt(
    const uint8_t key[CHACHAPOLY_KEY_SIZE],
    const uint8_t nonce[CHACHAPOLY_NONCE_SIZE],
    const uint8_t *ad, size_t ad_len,
    const uint8_t *plaintext, size_t pt_len,
    uint8_t *ciphertext
) {
    chacha_ctx chacha;
    poly1305_context poly;
    uint8_t poly_key[64];
    uint8_t block0_counter[8] = {0};
    uint8_t block1_counter[8] = {1, 0, 0, 0, 0, 0, 0, 0};
    uint8_t len_block[16];
    
    /* Generate Poly1305 key from first ChaCha20 block (counter = 0) */
    chacha_keysetup(&chacha, key, 256);
    chacha_ivsetup(&chacha, nonce + 4, block0_counter);
    memset(poly_key, 0, 64);
    chacha_encrypt_bytes(&chacha, poly_key, poly_key, 64);
    
    /* Encrypt plaintext with ChaCha20 (counter = 1) */
    chacha_keysetup(&chacha, key, 256);
    chacha_ivsetup(&chacha, nonce + 4, block1_counter);
    if (pt_len > 0) {
        chacha_encrypt_bytes(&chacha, plaintext, ciphertext, (uint32_t)pt_len);
    }
    
    /* Compute Poly1305 tag */
    poly1305_init(&poly, poly_key);
    
    /* Authenticate AD */
    if (ad_len > 0) {
        poly1305_update(&poly, ad, ad_len);
        poly1305_pad16(&poly, ad_len);
    }
    
    /* Authenticate ciphertext */
    if (pt_len > 0) {
        poly1305_update(&poly, ciphertext, pt_len);
        poly1305_pad16(&poly, pt_len);
    }
    
    /* Authenticate lengths */
    write_le64(len_block, ad_len);
    write_le64(len_block + 8, pt_len);
    poly1305_update(&poly, len_block, 16);
    
    /* Output tag */
    poly1305_finish(&poly, ciphertext + pt_len);
    
    /* Clean up sensitive data */
    secure_zero(&chacha, sizeof(chacha));
    secure_zero(poly_key, sizeof(poly_key));
    
    return pt_len + CHACHAPOLY_TAG_SIZE;
}

size_t chachapoly_decrypt(
    const uint8_t key[CHACHAPOLY_KEY_SIZE],
    const uint8_t nonce[CHACHAPOLY_NONCE_SIZE],
    const uint8_t *ad, size_t ad_len,
    const uint8_t *ciphertext, size_t ct_len,
    uint8_t *plaintext
) {
    chacha_ctx chacha;
    poly1305_context poly;
    uint8_t poly_key[64];
    uint8_t block0_counter[8] = {0};
    uint8_t block1_counter[8] = {1, 0, 0, 0, 0, 0, 0, 0};
    uint8_t len_block[16];
    uint8_t computed_tag[16];
    size_t pt_len;
    
    if (ct_len < CHACHAPOLY_TAG_SIZE) {
        return 0;
    }
    
    pt_len = ct_len - CHACHAPOLY_TAG_SIZE;
    
    /* Generate Poly1305 key from first ChaCha20 block (counter = 0) */
    chacha_keysetup(&chacha, key, 256);
    chacha_ivsetup(&chacha, nonce + 4, block0_counter);
    memset(poly_key, 0, 64);
    chacha_encrypt_bytes(&chacha, poly_key, poly_key, 64);
    
    /* Compute Poly1305 tag */
    poly1305_init(&poly, poly_key);
    
    /* Authenticate AD */
    if (ad_len > 0) {
        poly1305_update(&poly, ad, ad_len);
        poly1305_pad16(&poly, ad_len);
    }
    
    /* Authenticate ciphertext */
    if (pt_len > 0) {
        poly1305_update(&poly, ciphertext, pt_len);
        poly1305_pad16(&poly, pt_len);
    }
    
    /* Authenticate lengths */
    write_le64(len_block, ad_len);
    write_le64(len_block + 8, pt_len);
    poly1305_update(&poly, len_block, 16);
    
    /* Compute and verify tag */
    poly1305_finish(&poly, computed_tag);
    
    if (!secure_compare(computed_tag, ciphertext + pt_len, CHACHAPOLY_TAG_SIZE)) {
        secure_zero(&chacha, sizeof(chacha));
        secure_zero(poly_key, sizeof(poly_key));
        secure_zero(computed_tag, sizeof(computed_tag));
        return 0;  /* Authentication failed */
    }
    
    /* Decrypt ciphertext */
    chacha_keysetup(&chacha, key, 256);
    chacha_ivsetup(&chacha, nonce + 4, block1_counter);
    if (pt_len > 0) {
        chacha_encrypt_bytes(&chacha, ciphertext, plaintext, (uint32_t)pt_len);
    }
    
    /* Clean up sensitive data */
    secure_zero(&chacha, sizeof(chacha));
    secure_zero(poly_key, sizeof(poly_key));
    secure_zero(computed_tag, sizeof(computed_tag));
    
    return pt_len;
}

size_t chachapoly_encrypt_inplace(
    const uint8_t key[CHACHAPOLY_KEY_SIZE],
    const uint8_t nonce[CHACHAPOLY_NONCE_SIZE],
    const uint8_t *ad, size_t ad_len,
    uint8_t *data, size_t data_len
) {
    return chachapoly_encrypt(key, nonce, ad, ad_len, data, data_len, data);
}

size_t chachapoly_decrypt_inplace(
    const uint8_t key[CHACHAPOLY_KEY_SIZE],
    const uint8_t nonce[CHACHAPOLY_NONCE_SIZE],
    const uint8_t *ad, size_t ad_len,
    uint8_t *data, size_t data_len
) {
    return chachapoly_decrypt(key, nonce, ad, ad_len, data, data_len, data);
}
