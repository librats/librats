/*
 * HKDF-SHA256 implementation for Noise Protocol
 * Based on RFC 5869
 */

#include "hkdf.h"
#include "sha256.h"
#include <string.h>

#define SHA256_BLOCK_SIZE 64
#define SHA256_HASH_SIZE 32

/* Zero memory securely */
static void secure_zero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

void hmac_sha256(
    const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len,
    uint8_t output[HKDF_SHA256_HASH_LEN]
) {
    sha256_context_t ctx;
    uint8_t k_pad[SHA256_BLOCK_SIZE];
    uint8_t temp_key[SHA256_HASH_SIZE];
    const uint8_t *k;
    size_t k_len;
    size_t i;
    
    /* If key is longer than block size, hash it first */
    if (key_len > SHA256_BLOCK_SIZE) {
        sha256_hash(temp_key, key, key_len);
        k = temp_key;
        k_len = SHA256_HASH_SIZE;
    } else {
        k = key;
        k_len = key_len;
    }
    
    /* Prepare inner padding (key XOR 0x36) */
    memset(k_pad, 0x36, SHA256_BLOCK_SIZE);
    for (i = 0; i < k_len; i++) {
        k_pad[i] ^= k[i];
    }
    
    /* Inner hash: H(K XOR ipad || data) */
    sha256_reset(&ctx);
    sha256_update(&ctx, k_pad, SHA256_BLOCK_SIZE);
    sha256_update(&ctx, data, data_len);
    sha256_finish(&ctx, output);
    
    /* Prepare outer padding (key XOR 0x5c) */
    memset(k_pad, 0x5c, SHA256_BLOCK_SIZE);
    for (i = 0; i < k_len; i++) {
        k_pad[i] ^= k[i];
    }
    
    /* Outer hash: H(K XOR opad || inner_hash) */
    sha256_reset(&ctx);
    sha256_update(&ctx, k_pad, SHA256_BLOCK_SIZE);
    sha256_update(&ctx, output, SHA256_HASH_SIZE);
    sha256_finish(&ctx, output);
    
    /* Clean up */
    secure_zero(k_pad, sizeof(k_pad));
    secure_zero(temp_key, sizeof(temp_key));
}

void hmac_sha256_2(
    const uint8_t *key, size_t key_len,
    const uint8_t *data1, size_t data1_len,
    const uint8_t *data2, size_t data2_len,
    uint8_t output[HKDF_SHA256_HASH_LEN]
) {
    sha256_context_t ctx;
    uint8_t k_pad[SHA256_BLOCK_SIZE];
    uint8_t temp_key[SHA256_HASH_SIZE];
    const uint8_t *k;
    size_t k_len;
    size_t i;
    
    /* If key is longer than block size, hash it first */
    if (key_len > SHA256_BLOCK_SIZE) {
        sha256_hash(temp_key, key, key_len);
        k = temp_key;
        k_len = SHA256_HASH_SIZE;
    } else {
        k = key;
        k_len = key_len;
    }
    
    /* Prepare inner padding (key XOR 0x36) */
    memset(k_pad, 0x36, SHA256_BLOCK_SIZE);
    for (i = 0; i < k_len; i++) {
        k_pad[i] ^= k[i];
    }
    
    /* Inner hash: H(K XOR ipad || data1 || data2) */
    sha256_reset(&ctx);
    sha256_update(&ctx, k_pad, SHA256_BLOCK_SIZE);
    sha256_update(&ctx, data1, data1_len);
    sha256_update(&ctx, data2, data2_len);
    sha256_finish(&ctx, output);
    
    /* Prepare outer padding (key XOR 0x5c) */
    memset(k_pad, 0x5c, SHA256_BLOCK_SIZE);
    for (i = 0; i < k_len; i++) {
        k_pad[i] ^= k[i];
    }
    
    /* Outer hash: H(K XOR opad || inner_hash) */
    sha256_reset(&ctx);
    sha256_update(&ctx, k_pad, SHA256_BLOCK_SIZE);
    sha256_update(&ctx, output, SHA256_HASH_SIZE);
    sha256_finish(&ctx, output);
    
    /* Clean up */
    secure_zero(k_pad, sizeof(k_pad));
    secure_zero(temp_key, sizeof(temp_key));
}

void hkdf_sha256_extract(
    const uint8_t *salt, size_t salt_len,
    const uint8_t *ikm, size_t ikm_len,
    uint8_t prk[HKDF_SHA256_HASH_LEN]
) {
    static const uint8_t default_salt[HKDF_SHA256_HASH_LEN] = {0};
    
    if (salt == NULL || salt_len == 0) {
        salt = default_salt;
        salt_len = HKDF_SHA256_HASH_LEN;
    }
    
    hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
}

void hkdf_sha256_expand(
    const uint8_t prk[HKDF_SHA256_HASH_LEN],
    const uint8_t *info, size_t info_len,
    uint8_t *okm, size_t okm_len
) {
    sha256_context_t ctx;
    uint8_t k_pad[SHA256_BLOCK_SIZE];
    uint8_t T[SHA256_HASH_SIZE];
    uint8_t counter;
    size_t t_len = 0;
    size_t copy_len;
    size_t i;
    
    /* Key is always 32 bytes (hash length) */
    /* Prepare inner padding template */
    memset(k_pad, 0x36, SHA256_BLOCK_SIZE);
    for (i = 0; i < HKDF_SHA256_HASH_LEN; i++) {
        k_pad[i] ^= prk[i];
    }
    
    counter = 1;
    while (okm_len > 0) {
        uint8_t outer_result[SHA256_HASH_SIZE];
        uint8_t k_pad_outer[SHA256_BLOCK_SIZE];
        
        /* Inner hash: H(K XOR ipad || T || info || counter) */
        sha256_reset(&ctx);
        sha256_update(&ctx, k_pad, SHA256_BLOCK_SIZE);
        if (t_len > 0) {
            sha256_update(&ctx, T, t_len);
        }
        if (info_len > 0) {
            sha256_update(&ctx, info, info_len);
        }
        sha256_update(&ctx, &counter, 1);
        sha256_finish(&ctx, T);
        
        /* Prepare outer padding */
        memset(k_pad_outer, 0x5c, SHA256_BLOCK_SIZE);
        for (i = 0; i < HKDF_SHA256_HASH_LEN; i++) {
            k_pad_outer[i] ^= prk[i];
        }
        
        /* Outer hash: H(K XOR opad || inner_hash) */
        sha256_reset(&ctx);
        sha256_update(&ctx, k_pad_outer, SHA256_BLOCK_SIZE);
        sha256_update(&ctx, T, SHA256_HASH_SIZE);
        sha256_finish(&ctx, T);
        
        /* Copy to output */
        copy_len = okm_len < SHA256_HASH_SIZE ? okm_len : SHA256_HASH_SIZE;
        memcpy(okm, T, copy_len);
        okm += copy_len;
        okm_len -= copy_len;
        
        t_len = SHA256_HASH_SIZE;
        counter++;
        
        secure_zero(k_pad_outer, sizeof(k_pad_outer));
    }
    
    secure_zero(k_pad, sizeof(k_pad));
    secure_zero(T, sizeof(T));
}

void hkdf_sha256(
    const uint8_t *salt, size_t salt_len,
    const uint8_t *ikm, size_t ikm_len,
    const uint8_t *info, size_t info_len,
    uint8_t *okm, size_t okm_len
) {
    uint8_t prk[HKDF_SHA256_HASH_LEN];
    
    hkdf_sha256_extract(salt, salt_len, ikm, ikm_len, prk);
    hkdf_sha256_expand(prk, info, info_len, okm, okm_len);
    
    secure_zero(prk, sizeof(prk));
}

void noise_hkdf_2(
    const uint8_t chaining_key[HKDF_SHA256_HASH_LEN],
    const uint8_t *input_key, size_t input_len,
    uint8_t output1[HKDF_SHA256_HASH_LEN],
    uint8_t output2[HKDF_SHA256_HASH_LEN]
) {
    uint8_t temp_key[HKDF_SHA256_HASH_LEN];
    uint8_t counter1 = 0x01;
    uint8_t counter2 = 0x02;
    
    /* temp_key = HMAC(ck, input) */
    hmac_sha256(chaining_key, HKDF_SHA256_HASH_LEN, input_key, input_len, temp_key);
    
    /* output1 = HMAC(temp_key, 0x01) */
    hmac_sha256(temp_key, HKDF_SHA256_HASH_LEN, &counter1, 1, output1);
    
    /* output2 = HMAC(temp_key, output1 || 0x02) */
    hmac_sha256_2(temp_key, HKDF_SHA256_HASH_LEN, output1, HKDF_SHA256_HASH_LEN, &counter2, 1, output2);
    
    secure_zero(temp_key, sizeof(temp_key));
}

void noise_hkdf_3(
    const uint8_t chaining_key[HKDF_SHA256_HASH_LEN],
    const uint8_t *input_key, size_t input_len,
    uint8_t output1[HKDF_SHA256_HASH_LEN],
    uint8_t output2[HKDF_SHA256_HASH_LEN],
    uint8_t output3[HKDF_SHA256_HASH_LEN]
) {
    uint8_t temp_key[HKDF_SHA256_HASH_LEN];
    uint8_t counter1 = 0x01;
    uint8_t counter2 = 0x02;
    uint8_t counter3 = 0x03;
    
    /* temp_key = HMAC(ck, input) */
    hmac_sha256(chaining_key, HKDF_SHA256_HASH_LEN, input_key, input_len, temp_key);
    
    /* output1 = HMAC(temp_key, 0x01) */
    hmac_sha256(temp_key, HKDF_SHA256_HASH_LEN, &counter1, 1, output1);
    
    /* output2 = HMAC(temp_key, output1 || 0x02) */
    hmac_sha256_2(temp_key, HKDF_SHA256_HASH_LEN, output1, HKDF_SHA256_HASH_LEN, &counter2, 1, output2);
    
    /* output3 = HMAC(temp_key, output2 || 0x03) */
    hmac_sha256_2(temp_key, HKDF_SHA256_HASH_LEN, output2, HKDF_SHA256_HASH_LEN, &counter3, 1, output3);
    
    secure_zero(temp_key, sizeof(temp_key));
}
