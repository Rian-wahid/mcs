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
#include<mcs_mac.h>

void mcs_mac_init(mcs_mac_t *mac,const uint8_t key[32]){

	uint32_t *ik=(uint32_t *)&key[0];
	mac->k1=HTOLE32(ik[0]);
	mac->k2=HTOLE32(ik[1]);
	mac->k3=HTOLE32(ik[2]);
	mac->k4=HTOLE32(ik[3]);

	mac->k5=HTOLE32(ik[4]);
	mac->k6=HTOLE32(ik[5]);
	mac->k7=HTOLE32(ik[6]);
	mac->k8=HTOLE32(ik[7]);
	mac->a=mac->k5;
	mac->b=mac->k6;
	mac->c=mac->k7;
	mac->d=mac->k8;
	mac->counter_lo=0;
	mac->counter_hi=0;
	memset(mac->buf,0,16);
	mac->buf_len=0;


}
void mcs_mac_mix(uint32_t *ia,uint32_t *ib,uint32_t *ic,uint32_t *id){


	uint32_t a=*ia;
	uint32_t b=*ib;
	uint32_t c=*ic;
	uint32_t d=*id;

	a^=b;
	a=(a<<15)|(a>>17);
	d+=a;
	c^=d;
	c=(c<<12)|(c>>20);
	b+=c;

	a^=b;
	a=(a<<9)|(a>>23);
	d+=a;
	c^=d;
	c=(c<<6)|(c>>26);
	b+=c;

	a^=b;
	a=(a<<3)|(a>>29);
	d+=a;
	c^=d;
	c=(c<<1)|(c>>31);
	b+=c;

	

	*ia=a;
	*ib=b;
	*ic=c;
	*id=d;
}

void mcs_mac_calc(mcs_mac_t *mac,const uint8_t input[16]){

	uint32_t *in=(uint32_t *)&input[0];
	uint32_t a=HTOLE32(in[0]);
	uint32_t b=HTOLE32(in[1]);
	uint32_t c=HTOLE32(in[2]);
	uint32_t d=HTOLE32(in[3]);

	a^=mac->a;
	b^=mac->b;
	c^=mac->c;
	d^=mac->d;
	mcs_mac_mix(&a,&b,&c,&d);
	a^=mac->k1;
	b^=mac->k2;
	c^=mac->k3;
	d^=mac->k4;
	mcs_mac_mix(&a,&b,&c,&d);
	mac->a=a;
	mac->b=b;
	mac->c=c;
	mac->d=d;
	
}

void mcs_mac_write(mcs_mac_t *mac,const uint8_t *input,uint64_t len){

	mac->counter_lo+=len;
	uint64_t cr=(mac->counter_lo<len)?1:0;
	mac->counter_hi+=cr;

	// Handle existing buffered data
	if (mac->buf_len > 0) {
		size_t remaining_buf_space = sizeof(mac->buf) - mac->buf_len;
		if (len >= remaining_buf_space) {
			memcpy(mac->buf + mac->buf_len, input, remaining_buf_space);
			mcs_mac_calc(mac, mac->buf);
			input += remaining_buf_space;
			len -= remaining_buf_space;
			mac->buf_len = 0;
		} else {
			memcpy(mac->buf + mac->buf_len, input, len);
			mac->buf_len += len;
			return;
		}
	}

	// Process full 16-byte blocks from the remaining input
	while (len >= sizeof(mac->buf)) {
		mcs_mac_calc(mac, input);
		input += sizeof(mac->buf);
		len -= sizeof(mac->buf);
	}

	// Buffer any remaining partial input
	if (len > 0) {
		memcpy(mac->buf, input, len);
		mac->buf_len = len;
	}
}

void mcs_mac_calc_final(mcs_mac_t *mac){

	if(mac->buf_len!=0){
		mcs_mac_calc(mac,mac->buf);
	}
	uint8_t buf[16];
	uint64_t a=((uint64_t)mac->k5)|(((uint64_t)mac->k6)<<32);
	uint64_t b=((uint64_t)mac->k7)|(((uint64_t)mac->k8)<<32);
	a+=mac->counter_lo;
	b+=mac->counter_hi;
	uint64_t cr=(a<mac->counter_lo)?1:0;
	b+=cr;
	memcpy(buf,&a,8);
	memcpy(&buf[8],&b,8);
	mcs_mac_calc(mac,buf);
}

void mcs_mac_digest(mcs_mac_t *mac,uint8_t dst[16]){

	mcs_mac_calc_final(mac);
	uint32_t *out=(uint32_t *)&dst[0];
	out[0]=LETOH32(mac->a);
	out[1]=LETOH32(mac->b);
	out[2]=LETOH32(mac->c);
	out[3]=LETOH32(mac->d);
}

int mcs_mac_verify(mcs_mac_t *mac,const uint8_t tag[16]){

	uint8_t buf[16]={0};
	mcs_mac_digest(mac,buf);;
	uint64_t *out=(uint64_t *)&buf[0];
	uint64_t *expect=(uint64_t *)&tag[0];
	out[0]^=expect[0];
	out[1]^=expect[1];
	out[0]|=out[1];
	return (out[0]==0)?1:0;
}


