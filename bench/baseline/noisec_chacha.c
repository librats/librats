/* noise-c ChaCha20 reference, symbol-isolated. See noisec.h. */
#define chacha_keysetup      ncref_chacha_keysetup
#define chacha_ivsetup       ncref_chacha_ivsetup
#define chacha_encrypt_bytes ncref_chacha_encrypt_bytes
#include "../../reference2/src/crypto/chacha/chacha.c"
#include "noisec.h"

void nc_chacha20(uint8_t* out, const uint8_t* in, size_t len,
                 const uint8_t key[32], const uint8_t iv[8], const uint8_t counter[8]) {
    chacha_ctx x;
    ncref_chacha_keysetup(&x, key, 256);
    ncref_chacha_ivsetup(&x, iv, counter);
    ncref_chacha_encrypt_bytes(&x, in, out, (uint32_t)len);
}
