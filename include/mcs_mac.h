/*
 
MIT License

Copyright (c) 2026 Rian Wahid Prayogo r14n4r1e5@gmail.com

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


*/

#include<stdint.h>
#include<string.h>

// Endianness detection and byte swap
#if defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__)
#include <endian.h>
#if __BYTE_ORDER == __BIG_ENDIAN
#define HTOLE32(x) htole32(x)
#define LETOH32(x) le32toh(x)
#else
#define HTOLE32(x) (x)
#define LETOH32(x) (x)
#endif
#elif defined(_WIN32)
#include <intrin.h> // For _byteswap_ulong
// Windows on x86/x64 is little-endian, so no swap for HTOLE and LETOH
#define HTOLE32(x) (x)
#define LETOH32(x) (x)
#else
// Generic fallback if endianness cannot be determined or intrinsics are not available
// Assumes little-endian by default for simplicity, but a proper check might be needed
#warning "Could not determine system endianness. Assuming little-endian."
#define HTOLE32(x) (x)
#define LETOH32(x) (x)
#endif

typedef struct{

	uint32_t a,b,c,d;
	uint32_t k1,k2,k3,k4;
	uint32_t k5,k6,k7,k8;
	uint64_t counter_lo;
	uint64_t counter_hi;
	uint8_t buf[16];
	size_t buf_len;
}mcs_mac_t;
// initialize mac
void mcs_mac_init(mcs_mac_t *mac,const uint8_t key[32]);

// compute flexible length input to the state
void mcs_mac_write(mcs_mac_t *mac,const uint8_t *input,uint64_t len);

// create mac tag
void mcs_mac_digest(mcs_mac_t *mac,uint8_t dst[16]);

// verify mac tag
int mcs_mac_verify(mcs_mac_t *mac,const uint8_t tag[16]);
