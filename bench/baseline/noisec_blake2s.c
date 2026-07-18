/* noise-c BLAKE2s reference, symbol-isolated. See noisec.h. */
#define BLAKE2s_reset  ncref_BLAKE2s_reset
#define BLAKE2s_update ncref_BLAKE2s_update
#define BLAKE2s_finish ncref_BLAKE2s_finish
#include "../../reference2/src/crypto/blake2/blake2s.c"
#include "noisec.h"

void nc_blake2s(uint8_t out[32], const void* data, size_t len) {
    BLAKE2s_context_t c;
    ncref_BLAKE2s_reset(&c);
    ncref_BLAKE2s_update(&c, data, len);
    ncref_BLAKE2s_finish(&c, out);
}
