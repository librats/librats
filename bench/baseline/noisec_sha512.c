/* noise-c SHA-512 reference, symbol-isolated. See noisec.h. */
#define sha512_reset  ncref_sha512_reset
#define sha512_update ncref_sha512_update
#define sha512_finish ncref_sha512_finish
#define sha512_hash   ncref_sha512_hash
#include "../../reference2/src/crypto/sha2/sha512.c"
#include "noisec.h"

void nc_sha512(uint8_t out[64], const void* data, size_t len) {
    sha512_context_t c;
    ncref_sha512_reset(&c);
    ncref_sha512_update(&c, data, len);
    ncref_sha512_finish(&c, out);
}
