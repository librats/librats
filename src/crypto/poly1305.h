/* SPDX-License-Identifier: MIT */
/*
 * poly1305-donna
 * https://github.com/floodyberry/poly1305-donna
 * MIT license / public domain
 */

#ifndef LIBRATS_POLY1305_H
#define LIBRATS_POLY1305_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RATS_POLY1305_KEY_SIZE 32
#define RATS_POLY1305_TAG_SIZE 16

typedef struct rats_poly1305_context {
    size_t aligner;
    unsigned char opaque[136];
} rats_poly1305_context;

void rats_poly1305_init(rats_poly1305_context *ctx, const unsigned char key[32]);
void rats_poly1305_update(rats_poly1305_context *ctx, const unsigned char *m, size_t bytes);
void rats_poly1305_finish(rats_poly1305_context *ctx, unsigned char mac[16]);
void rats_poly1305_auth(unsigned char mac[16], const unsigned char *m, size_t bytes, const unsigned char key[32]);

int rats_poly1305_verify(const unsigned char mac1[16], const unsigned char mac2[16]);
int rats_poly1305_power_on_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* LIBRATS_POLY1305_H */
