/*
 * HKDF-SHA256 implementation for Noise Protocol
 * Based on RFC 5869
 */

#ifndef RATS_HKDF_H
#define RATS_HKDF_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HKDF_SHA256_HASH_LEN 32

/**
 * HMAC-SHA256 function
 * 
 * @param key      Key for HMAC
 * @param key_len  Length of key
 * @param data     Data to authenticate
 * @param data_len Length of data
 * @param output   Output buffer (32 bytes)
 */
void hmac_sha256(
    const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len,
    uint8_t output[HKDF_SHA256_HASH_LEN]
);

/**
 * HMAC-SHA256 with two data inputs (concatenated)
 * 
 * @param key       Key for HMAC
 * @param key_len   Length of key
 * @param data1     First data block
 * @param data1_len Length of first data block
 * @param data2     Second data block
 * @param data2_len Length of second data block
 * @param output    Output buffer (32 bytes)
 */
void hmac_sha256_2(
    const uint8_t *key, size_t key_len,
    const uint8_t *data1, size_t data1_len,
    const uint8_t *data2, size_t data2_len,
    uint8_t output[HKDF_SHA256_HASH_LEN]
);

/**
 * HKDF-SHA256 Extract (RFC 5869)
 * 
 * @param salt     Optional salt (if NULL, uses zeros)
 * @param salt_len Length of salt
 * @param ikm      Input keying material
 * @param ikm_len  Length of IKM
 * @param prk      Output pseudorandom key (32 bytes)
 */
void hkdf_sha256_extract(
    const uint8_t *salt, size_t salt_len,
    const uint8_t *ikm, size_t ikm_len,
    uint8_t prk[HKDF_SHA256_HASH_LEN]
);

/**
 * HKDF-SHA256 Expand (RFC 5869)
 * 
 * @param prk      Pseudorandom key (32 bytes)
 * @param info     Optional context info (may be NULL)
 * @param info_len Length of info
 * @param okm      Output keying material
 * @param okm_len  Length of OKM (max 255 * 32 = 8160 bytes)
 */
void hkdf_sha256_expand(
    const uint8_t prk[HKDF_SHA256_HASH_LEN],
    const uint8_t *info, size_t info_len,
    uint8_t *okm, size_t okm_len
);

/**
 * HKDF-SHA256 (full Extract + Expand)
 * 
 * @param salt     Optional salt (if NULL, uses zeros)
 * @param salt_len Length of salt
 * @param ikm      Input keying material
 * @param ikm_len  Length of IKM
 * @param info     Optional context info (may be NULL)
 * @param info_len Length of info
 * @param okm      Output keying material
 * @param okm_len  Length of OKM
 */
void hkdf_sha256(
    const uint8_t *salt, size_t salt_len,
    const uint8_t *ikm, size_t ikm_len,
    const uint8_t *info, size_t info_len,
    uint8_t *okm, size_t okm_len
);

/**
 * Noise Protocol HKDF: derives 2 keys from chaining key and input
 * HKDF(ck, input) -> (output1, output2)
 * Uses empty info for Noise
 * 
 * @param chaining_key Current chaining key (32 bytes)
 * @param input_key    Input key material
 * @param input_len    Length of input
 * @param output1      First output key (32 bytes)
 * @param output2      Second output key (32 bytes)
 */
void noise_hkdf_2(
    const uint8_t chaining_key[HKDF_SHA256_HASH_LEN],
    const uint8_t *input_key, size_t input_len,
    uint8_t output1[HKDF_SHA256_HASH_LEN],
    uint8_t output2[HKDF_SHA256_HASH_LEN]
);

/**
 * Noise Protocol HKDF: derives 3 keys from chaining key and input
 * Used by split() operation
 * 
 * @param chaining_key Current chaining key (32 bytes)
 * @param input_key    Input key material
 * @param input_len    Length of input
 * @param output1      First output key (32 bytes)
 * @param output2      Second output key (32 bytes)
 * @param output3      Third output key (32 bytes)
 */
void noise_hkdf_3(
    const uint8_t chaining_key[HKDF_SHA256_HASH_LEN],
    const uint8_t *input_key, size_t input_len,
    uint8_t output1[HKDF_SHA256_HASH_LEN],
    uint8_t output2[HKDF_SHA256_HASH_LEN],
    uint8_t output3[HKDF_SHA256_HASH_LEN]
);

#ifdef __cplusplus
}
#endif

#endif /* RATS_HKDF_H */
