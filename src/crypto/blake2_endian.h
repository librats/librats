/* SPDX-License-Identifier: MIT */
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

#ifndef LIBRATS_BLAKE2_ENDIAN_H
#define LIBRATS_BLAKE2_ENDIAN_H

/*
 * Defines RATS_BLAKE2_LITTLE_ENDIAN when the target is little-endian, and
 * nothing else. This header is installed, so it must NOT define __BYTE_ORDER /
 * __LITTLE_ENDIAN / __BIG_ENDIAN: those names are reserved to the platform, and
 * defining them here leaks into every consumer translation unit that includes
 * us. Detect the byte order instead of asserting it.
 */

#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__)
/* GCC and Clang predefine these on every target — no system header needed. */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define RATS_BLAKE2_LITTLE_ENDIAN 1
#endif
#elif defined(_WIN32)
/* MSVC predefines no byte-order macro; every Windows target it ships is LE. */
#define RATS_BLAKE2_LITTLE_ENDIAN 1
#elif defined(__APPLE__)
#include <machine/endian.h>
#if __DARWIN_BYTE_ORDER == __DARWIN_LITTLE_ENDIAN
#define RATS_BLAKE2_LITTLE_ENDIAN 1
#endif
#else
#include <endian.h>
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define RATS_BLAKE2_LITTLE_ENDIAN 1
#endif
#endif

#endif /* LIBRATS_BLAKE2_ENDIAN_H */
