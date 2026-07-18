/* noise-c Curve25519 (donna) reference, symbol-isolated. See noisec.h. */
#define curve25519_donna ncref_curve25519_donna
#include "../../reference2/src/crypto/donna/curve25519-donna.c"
#include "noisec.h"

int nc_curve25519(uint8_t out[32], const uint8_t secret[32], const uint8_t basepoint[32]) {
    return ncref_curve25519_donna(out, secret, basepoint);
}
