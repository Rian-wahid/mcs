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


#include<string.h>
#include<mcs_cipher.h>
#include<assert.h>
#include<stdio.h>

#define CONST_A 0xbd5bc326d7b42f7bLU
#define CONST_B 0x7a73cb2b5b7c27c0LU
#define CONST_C 0x4d6af9625ec1db68LU
#define CONST_D 0x6828f43bfe0143bbLU

void mcs_confuse(uint64_t *ia,uint64_t *ib,uint64_t *ic,uint64_t *id){


	uint64_t a=*ia;
	uint64_t b=*ib;
	uint64_t c=*ic;
	uint64_t d=*id;


	a^=b;
	a=(a<<31)|(a>>33);
	d+=a;
	c^=d;
	c=(c<<28)|(c>>36);
	b+=c;

	a^=b;
	a=(a<<25)|(a>>39);
	d+=a;
	c^=d;
	c=(c<<22)|(c>>42);
	b+=c;

	a^=b;
	a=(a<<19)|(a>>45);
	d+=a;
	c^=d;
	c=(c<<16)|(c>>48);
	b+=c;

	a^=b;
	a=(a<<13)|(a>>51);
	d+=a;
	c^=d;
	c=(c<<11)|(c>>53);
	b+=c;


	a^=b;
	a=(a<<8)|(a>>56);
	d+=a;
	c^=d;
	c=(c<<5)|(c>>59);
	b+=c;
	

	a^=b;
	a=(a<<4)|(a>>60);
	d+=a;
	c^=d;
	c=(c<<3)|(c>>61);
	b+=c;

	*ia=a;
	*ib=b;
	*ic=c;
	*id=d;
}

void mcs_mix(uint64_t *ia,uint64_t *ib,uint64_t *ic,uint64_t *id){
	uint64_t a=*ia;
	uint64_t b=*ib;
	uint64_t c=*ic;
	uint64_t d=*id;


	a^=b;
	a=(a<<31)|(a>>33);
	d+=a;
	c^=d;
	c=(c<<23)|(c>>41);
	b+=c;

	a^=b;
	a=(a<<15)|(a>>49);
	d+=a;
	c^=d;
	c=(c<<7)|(c>>57);
	b+=c;

	a^=b;
	a=(a<<5)|(a>>59);
	d+=a;
	c^=d;
	c=(c<<3)|(c>>61);
	b+=c;
	

	*ia=a;
	*ib=b;
	*ic=c;
	*id=d;
	
}

void mcs_anti_invers(uint64_t *ia,uint64_t *ib,uint64_t *ic,uint64_t *id){
	uint64_t a=*ia;
	uint64_t b=*ib;
	uint64_t c=*ic;
	uint64_t d=*id;


	// operate 128 bit addition
	// tl is low
	// th is high
	uint64_t tl=a+c;
	uint64_t th=b+d;
	uint64_t cr=(tl<a)?1:0;
	th+=cr;

	// xoring a with tl, b with th,
	// c with ~tl, d with ~th
	a^=tl;
	b^=th;
	tl=~tl;
	th=~th;
	c^=tl;
	d^=th;
	// to inverse this process. tl and th must be brute forced. or some input is known
	// and it hard because 128 bit
	
	//this algorithm is already tested using small input output
	// and not have any collision
	
	// the algorithm is
	// t=a+b
	// a'=a^t
	// t'=~t
	// b'=b^t'
	// the output is a' and b'
	

	*ia=a;
	*ib=b;
	*ic=c;
	*id=d;
}

void mcs_cipher_init(mcs_cipher_t *cipher,uint8_t *key,uint8_t *nonce){

	//initialize struct value
	
	memset(cipher->buf,0,256);
	cipher->block_count=0;
	cipher->buf_offset=0;
	cipher->buf_len=0;

	uint64_t *ik=(uint64_t *)key;
	uint64_t *in=(uint64_t *)nonce;
	/* a b c d
	 * e f g h
	 * i j k l
	 * m n o p
	 */


	uint64_t a=CONST_A;
	uint64_t b=CONST_B;
	uint64_t c=CONST_C;
	uint64_t d=CONST_D;

	uint64_t e=HTOLE64(ik[0]);
	uint64_t f=HTOLE64(ik[1]);
	uint64_t g=HTOLE64(ik[2]);
	uint64_t h=HTOLE64(ik[3]);
	
	uint64_t i=HTOLE64(ik[0]);
	uint64_t j=HTOLE64(ik[1]);
	uint64_t k=HTOLE64(ik[2]);
	uint64_t l=HTOLE64(ik[3]);

	mcs_confuse(&i,&j,&k,&l);
	
	uint64_t m=HTOLE64(in[0]);
	uint64_t n=HTOLE64(in[1]);
	uint64_t o=HTOLE64(in[2]);
	uint64_t p=HTOLE64(in[3]);

	mcs_confuse(&a,&e,&i,&m);
	mcs_confuse(&b,&f,&j,&n);
	mcs_confuse(&c,&g,&k,&o);
	mcs_confuse(&d,&h,&l,&p);
	
	mcs_anti_invers(&a,&e,&i,&m);
	mcs_anti_invers(&b,&f,&j,&n);
	mcs_anti_invers(&c,&g,&k,&o);
	mcs_anti_invers(&d,&h,&l,&p);

	cipher->a=a;
	cipher->b=b;
	cipher->c=c;
	cipher->d=d;

	cipher->e=e;
	cipher->f=f;
	cipher->g=g;
	cipher->h=h;

	cipher->i=i;
	cipher->j=j;
	cipher->k=k;
	cipher->l=l;

	cipher->m=m;
	cipher->n=n;
	cipher->o=o;
	cipher->p=p;



	//generating anti invers key

	a=CONST_A;
	b=CONST_B;
	c=CONST_C;
	d=CONST_D;

	e=HTOLE64(~ik[0]);
	f=HTOLE64(~ik[1]);
	g=HTOLE64(~ik[2]);
	h=HTOLE64(~ik[3]);
	
	i=HTOLE64(~ik[0]);
	j=HTOLE64(~ik[1]);
	k=HTOLE64(~ik[2]);
	l=HTOLE64(~ik[3]);

	mcs_confuse(&i,&j,&k,&l);
	
	m=HTOLE64(~in[0]);
	n=HTOLE64(~in[1]);
	o=HTOLE64(~in[2]);
	p=HTOLE64(~in[3]);

	mcs_confuse(&a,&e,&i,&m);
	mcs_confuse(&b,&f,&j,&n);
	mcs_confuse(&c,&g,&k,&o);
	mcs_confuse(&d,&h,&l,&p);
	
	mcs_anti_invers(&a,&e,&i,&m);
	mcs_anti_invers(&b,&f,&j,&n);
	mcs_anti_invers(&c,&g,&k,&o);
	mcs_anti_invers(&d,&h,&l,&p);

	cipher->ka=a;
	cipher->kb=b;
	cipher->kc=c;
	cipher->kd=d;

	cipher->ke=e;
	cipher->kf=f;
	cipher->kg=g;
	cipher->kh=h;

	cipher->ki=i;
	cipher->kj=j;
	cipher->kk=k;
	cipher->kl=l;

	cipher->km=m;
	cipher->kn=n;
	cipher->ko=o;
	cipher->kp=p;
}
void mcs_cipher_xor_block(mcs_cipher_t *cipher,uint8_t *dst,uint8_t *src,uint64_t nb){

	uint64_t a=cipher->a;
	uint64_t b=cipher->b;
	uint64_t c=cipher->c;
	uint64_t d=cipher->d;

	uint64_t e=cipher->e;
	uint64_t f=cipher->f;
	uint64_t g=cipher->g;
	uint64_t h=cipher->h;


	uint64_t i=cipher->i;
	uint64_t j=cipher->j;
	uint64_t k=cipher->k;
	uint64_t l=cipher->l;


	// add block number 'nb' (counter) to m
	uint64_t m=cipher->m+nb;
	// Check for counter overflow
	if (nb > 0 && m < cipher->m) {
		fprintf(stderr, "MCS Cipher Counter Overflow Detected!\n");
		assert(0);
	}
	uint64_t n=cipher->n;
	uint64_t o=cipher->o;
	uint64_t p=cipher->p;

	/* a b c d
	 * e f g h
	 * i j k l
	 * m n o p
	 */
	mcs_confuse(&a,&e,&i,&m);
	// this make more harder to predict next or previous block output
	// without knowing the state
	a+=cipher->a;
	e+=cipher->e;
	i+=cipher->i;
	m+=cipher->m;

	mcs_confuse(&a,&f,&k,&p);
	mcs_confuse(&d,&g,&j,&m);
	mcs_confuse(&b,&h,&i,&o);
	mcs_confuse(&c,&e,&l,&n);

	mcs_confuse(&a,&h,&k,&n);
	mcs_confuse(&d,&e,&j,&o);
	mcs_confuse(&b,&g,&l,&m);
	mcs_confuse(&c,&f,&i,&p);

	for(int x=0; x<6; x++){


		mcs_mix(&a,&e,&i,&m);
		mcs_mix(&b,&f,&j,&n);
		mcs_mix(&c,&g,&k,&o);
		mcs_mix(&d,&h,&l,&p);

		mcs_mix(&a,&f,&k,&p);
		mcs_mix(&d,&g,&j,&m);
		mcs_mix(&b,&h,&i,&o);
		mcs_mix(&c,&e,&l,&n);
		
		mcs_mix(&a,&h,&k,&n);
		mcs_mix(&d,&e,&j,&o);
		mcs_mix(&b,&g,&l,&m);
		mcs_mix(&c,&f,&i,&p);

	}
	

	// add anti invers key. make it hard to invers the process
	a+=cipher->ka;
	b+=cipher->kb;
	c+=cipher->kc;
	d+=cipher->kd;

	e+=cipher->ke;
	f+=cipher->kf;
	g+=cipher->kg;
	h+=cipher->kh;

	i+=cipher->ki;
	j+=cipher->kj;
	k+=cipher->kk;
	l+=cipher->kl;

	m+=cipher->km;
	n+=cipher->kn;
	o+=cipher->ko;
	p+=cipher->kp;


	uint64_t *cpt=(uint64_t *)dst;
	uint64_t *plt=(uint64_t *)src;
	cpt[0]=LETOH64(HTOLE64(plt[0])^a);
	cpt[1]=LETOH64(HTOLE64(plt[1])^b);
	cpt[2]=LETOH64(HTOLE64(plt[2])^c);
	cpt[3]=LETOH64(HTOLE64(plt[3])^d);

	cpt[4]=LETOH64(HTOLE64(plt[4])^e);
	cpt[5]=LETOH64(HTOLE64(plt[5])^f);
	cpt[6]=LETOH64(HTOLE64(plt[6])^g);
	cpt[7]=LETOH64(HTOLE64(plt[7])^h);

	cpt[8]=LETOH64(HTOLE64(plt[8])^i);
	cpt[9]=LETOH64(HTOLE64(plt[9])^j);
	cpt[10]=LETOH64(HTOLE64(plt[10])^k);
	cpt[11]=LETOH64(HTOLE64(plt[11])^l);

	cpt[12]=LETOH64(HTOLE64(plt[12])^m);
	cpt[13]=LETOH64(HTOLE64(plt[13])^n);
	cpt[14]=LETOH64(HTOLE64(plt[14])^o);
	cpt[15]=LETOH64(HTOLE64(plt[15])^p);
}

void mcs_cipher_xor_stream(mcs_cipher_t *cipher,uint8_t *dst,const uint8_t *src,uint64_t len){
    uint8_t keystream_block[128];
    uint8_t zero_block[128] = {0}; // Dummy src for generating pure keystream
    size_t block_size = 128;

    // Use buffered keystream first
    if (cipher->buf_len > 0) {
        size_t bytes_from_buf = (len < cipher->buf_len) ? len : cipher->buf_len;
        for (size_t i = 0; i < bytes_from_buf; ++i) {
            dst[i] = src[i] ^ cipher->buf[cipher->buf_offset + i];
        }
        cipher->buf_offset += bytes_from_buf;
        cipher->buf_len -= bytes_from_buf;
        dst += bytes_from_buf;
        src += bytes_from_buf;
        len -= bytes_from_buf;
    }

    // Process full blocks
    while (len >= block_size) {
        mcs_cipher_xor_block(cipher, dst, (uint8_t*)src, cipher->block_count);
        cipher->block_count++;
        dst += block_size;
        src += block_size;
        len -= block_size;
    }

    // Handle remaining partial block
    if (len > 0) {
        // Generate a new full keystream block into keystream_block
        mcs_cipher_xor_block(cipher, keystream_block, zero_block, cipher->block_count);
        cipher->block_count++;

        // XOR with remaining src bytes and write to dst
        for (size_t i = 0; i < len; ++i) {
            dst[i] = src[i] ^ keystream_block[i];
        }
        
        // Store the unused portion of the keystream in cipher->buf
        memcpy(cipher->buf, keystream_block + len, block_size - len);
        cipher->buf_offset = 0;
        cipher->buf_len = block_size - len;
    }
}
