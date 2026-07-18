/* noise-c Poly1305 (donna) reference, symbol-isolated. See noisec.h. */
#define poly1305_init               ncref_poly1305_init
#define poly1305_update             ncref_poly1305_update
#define poly1305_finish             ncref_poly1305_finish
#define poly1305_auth               ncref_poly1305_auth
#define poly1305_verify             ncref_poly1305_verify
#define poly1305_power_on_self_test ncref_poly1305_power_on_self_test
#include "../../reference2/src/crypto/donna/poly1305-donna.c"
#include "noisec.h"

void nc_poly1305(uint8_t mac[16], const void* m, size_t len, const uint8_t key[32]) {
    ncref_poly1305_auth(mac, (const unsigned char*)m, len, key);
}
