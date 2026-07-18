/* noise-c SHA-256 reference, symbol-isolated. See noisec.h. */
#define sha256_reset  ncref_sha256_reset
#define sha256_update ncref_sha256_update
#define sha256_finish ncref_sha256_finish
#define sha256_hash   ncref_sha256_hash
#include "../../reference2/src/crypto/sha2/sha256.c"
#include "noisec.h"

void nc_sha256(uint8_t out[32], const void* data, size_t len) {
    sha256_context_t c;
    ncref_sha256_reset(&c);
    ncref_sha256_update(&c, data, len);
    ncref_sha256_finish(&c, out);
}
