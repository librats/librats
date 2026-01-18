/*
 * Copyright (C) 2016 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#ifndef LIBRATS_CHACHA_H
#define LIBRATS_CHACHA_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CHACHA_KEY_SIZE 32
#define CHACHA_NONCE_SIZE 8
#define CHACHA_BLOCK_SIZE 64

#if defined(__SSE2__) && defined(__GNUC__) && __GNUC__ >= 4
#define CHACHA_USE_VECTOR_MATH 1
#ifdef __clang__
typedef uint32_t ChaChaVectorUInt32 __attribute__((ext_vector_type(4)));
#else
typedef uint32_t ChaChaVectorUInt32 __attribute__((__vector_size__(16)));
#endif
#else
#undef CHACHA_USE_VECTOR_MATH
#endif

typedef struct
{
#ifdef CHACHA_USE_VECTOR_MATH
    ChaChaVectorUInt32 input[4];
#else
    uint32_t input[16];
#endif

} chacha_ctx;

void chacha_keysetup(chacha_ctx *x, const uint8_t *k, uint32_t kbits);
void chacha_ivsetup(chacha_ctx *x, const uint8_t *iv, const uint8_t *counter);
void chacha_encrypt_bytes(chacha_ctx *x, const uint8_t *m, uint8_t *c, uint32_t bytes);

#ifdef __cplusplus
}
#endif

#endif /* LIBRATS_CHACHA_H */
