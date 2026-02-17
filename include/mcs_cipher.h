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


typedef struct{

	/* a - p is the state to generate pseudo random bytes
	 * m is the counter. the counter is not start from 0.
	 * the m must not change to make it can run parallel in future
	 */
	uint64_t a,b,c,d;
	uint64_t e,f,g,h;
	uint64_t i,j,k,l;
	uint64_t m,n,o,p;

	/* ka - kp is the anti invers key.
	 * it add to output after all round is done
	 */
	uint64_t ka,kb,kc,kd;
	uint64_t ke,kf,kg,kh;
	uint64_t ki,kj,kk,kl;
	uint64_t km,kn,ko,kp;

	// temporary buffer that store key stream if previous input is not 128 bytes
	// or not multiple of 128 bytes
	uint8_t buf[256];

	// offset to next key stream in temporary buffer
	uint16_t buf_offset;
	
	// length of key stream in temporary buffer can be used for next input
	uint16_t buf_len;

	// a counter of outputted block
	uint64_t block_count;
}mcs_cipher_t;

// this fuction initialize cipher with 32 bytes key, 32 bytes nonce
void mcs_cipher_init(mcs_cipher_t *cipher,uint8_t *key,uint8_t *nonce);

// this function generate key stream and xor it to fixed length input (128 bytes)
// this function is used by mcs_cipher_xor_stream function
void mcs_cipher_xor_block(mcs_cipher_t *cipher,uint8_t *dst,uint8_t *src,uint64_t nb);

// this function generate key stream and xor it to flexible length input
// TODO: implement this function
//void mcs_cipher_xor_stream(mcs_cipher_t *cipher,uint8_t *dst,uint8_t *src);
