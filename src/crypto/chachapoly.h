/*
 * ChaCha20-Poly1305 AEAD construction for Noise Protocol
 * Based on RFC 8439
 */

#ifndef RATS_CHACHAPOLY_H
#define RATS_CHACHAPOLY_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CHACHAPOLY_KEY_SIZE 32
#define CHACHAPOLY_NONCE_SIZE 12
#define CHACHAPOLY_TAG_SIZE 16

/**
 * Encrypt plaintext with ChaCha20-Poly1305 AEAD
 * 
 * @param key       32-byte encryption key
 * @param nonce     12-byte nonce (must be unique per key)
 * @param ad        Additional authenticated data (may be NULL if ad_len is 0)
 * @param ad_len    Length of additional data
 * @param plaintext Input plaintext
 * @param pt_len    Length of plaintext
 * @param ciphertext Output buffer (must be at least pt_len + 16 bytes)
 * @return          Length of ciphertext (pt_len + 16) on success, 0 on failure
 */
size_t chachapoly_encrypt(
    const uint8_t key[CHACHAPOLY_KEY_SIZE],
    const uint8_t nonce[CHACHAPOLY_NONCE_SIZE],
    const uint8_t *ad, size_t ad_len,
    const uint8_t *plaintext, size_t pt_len,
    uint8_t *ciphertext
);

/**
 * Decrypt ciphertext with ChaCha20-Poly1305 AEAD
 * 
 * @param key        32-byte encryption key
 * @param nonce      12-byte nonce (same as used in encryption)
 * @param ad         Additional authenticated data (may be NULL if ad_len is 0)
 * @param ad_len     Length of additional data
 * @param ciphertext Input ciphertext (plaintext + 16-byte tag)
 * @param ct_len     Length of ciphertext (must be >= 16)
 * @param plaintext  Output buffer (must be at least ct_len - 16 bytes)
 * @return           Length of plaintext (ct_len - 16) on success, 0 on failure
 */
size_t chachapoly_decrypt(
    const uint8_t key[CHACHAPOLY_KEY_SIZE],
    const uint8_t nonce[CHACHAPOLY_NONCE_SIZE],
    const uint8_t *ad, size_t ad_len,
    const uint8_t *ciphertext, size_t ct_len,
    uint8_t *plaintext
);

/**
 * Encrypt in-place with ChaCha20-Poly1305 AEAD
 * The buffer must have 16 extra bytes for the tag
 * 
 * @param key       32-byte encryption key
 * @param nonce     12-byte nonce
 * @param ad        Additional authenticated data
 * @param ad_len    Length of additional data
 * @param data      Data buffer (plaintext in, ciphertext + tag out)
 * @param data_len  Length of plaintext
 * @return          Length of output (data_len + 16) on success, 0 on failure
 */
size_t chachapoly_encrypt_inplace(
    const uint8_t key[CHACHAPOLY_KEY_SIZE],
    const uint8_t nonce[CHACHAPOLY_NONCE_SIZE],
    const uint8_t *ad, size_t ad_len,
    uint8_t *data, size_t data_len
);

/**
 * Decrypt in-place with ChaCha20-Poly1305 AEAD
 * 
 * @param key       32-byte encryption key
 * @param nonce     12-byte nonce
 * @param ad        Additional authenticated data
 * @param ad_len    Length of additional data
 * @param data      Data buffer (ciphertext + tag in, plaintext out)
 * @param data_len  Length of ciphertext including tag (must be >= 16)
 * @return          Length of plaintext (data_len - 16) on success, 0 on failure
 */
size_t chachapoly_decrypt_inplace(
    const uint8_t key[CHACHAPOLY_KEY_SIZE],
    const uint8_t nonce[CHACHAPOLY_NONCE_SIZE],
    const uint8_t *ad, size_t ad_len,
    uint8_t *data, size_t data_len
);

#ifdef __cplusplus
}
#endif

#endif /* RATS_CHACHAPOLY_H */
