/* noise-c BLAKE2b reference, symbol-isolated. See noisec.h. */
#define BLAKE2b_reset  ncref_BLAKE2b_reset
#define BLAKE2b_update ncref_BLAKE2b_update
#define BLAKE2b_finish ncref_BLAKE2b_finish
#include "../../reference2/src/crypto/blake2/blake2b.c"
#include "noisec.h"

void nc_blake2b(uint8_t out[64], const void* data, size_t len) {
    BLAKE2b_context_t c;
    ncref_BLAKE2b_reset(&c);
    ncref_BLAKE2b_update(&c, data, len);
    ncref_BLAKE2b_finish(&c, out);
}
