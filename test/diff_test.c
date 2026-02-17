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
#include<stdio.h>
#include<string.h>
#include<linux/random.h>
#include<assert.h>
#include<malloc.h>
#include<mcs_cipher.h>
typedef struct{

	uint32_t fq4[256][16];
	uint32_t fq8[128][256];
	uint8_t outst[1025][128];
}diff_test_data_t;
extern ssize_t getrandom(void *buf,size_t size,unsigned int flags);
typedef struct{

	uint32_t exceed_limit_eq8;
	uint32_t exceed_limit_eq4;
	uint32_t exceed_limit_fq8;
	uint32_t exceed_limit_fq4;
	uint32_t full_diff8;
	uint32_t full_diff4;
	double max_eq8;
	double max_eq4;
	double max_fq8;
	double max_fq4;
	double avg_eq8;
	double avg_eq4;
	uint32_t exceed_limit_longest_bit_eq;
	uint32_t longest_bit_eq;
	

}test_info_t;


double compare4(uint8_t *a,uint8_t *b){
	double eq=0;
	for(int i=0; i<128; i++){
		if((a[i]&0xf0)==(b[i]&0xf0)){
			eq+=1;
		}
		if((a[i]&0x0f)==(b[i]&0x0f)){
			eq+=1;

		}

	}
	return eq/256;

}

double compare8(uint8_t *a,uint8_t *b){

	double eq=0;
	for(int i=0; i<128; i++){

		if(a[i]==b[i]){
			eq+=1;

		}
	}
	return eq/128;
}

void copy_state(mcs_cipher_t *dst,mcs_cipher_t *src){

	memcpy(dst,src,sizeof(mcs_cipher_t));
}

uint32_t longest_bit_eq(uint8_t *a,uint8_t *b){
	uint32_t res=0;
	uint32_t ceq=0;
	for(int i=0; i<128; i++){
		uint8_t byte=a[i]^b[i];
		for(int j=7; j>=0; j--){
			if(((byte>>j)&1)==0){
				ceq+=1;
				if(ceq>res){
					res=ceq;
				}
			}else{
				ceq=0;

			}

		}

	}
	return res;
}

void diff_test(uint8_t *key,uint8_t *nonce, test_info_t *tinfo){

	tinfo->avg_eq8=0;
	tinfo->avg_eq4=0;
	tinfo->max_fq8=0;
	tinfo->max_fq4=0;
	tinfo->max_eq8=0;
	tinfo->max_eq4=0;
	tinfo->full_diff8=0;
	tinfo->full_diff4=0;

	tinfo->exceed_limit_fq8=0;
	tinfo->exceed_limit_fq4=0;
	tinfo->exceed_limit_eq8=0;
	tinfo->exceed_limit_eq4=0;
	tinfo->exceed_limit_longest_bit_eq=0;
	tinfo->longest_bit_eq=0;
	
	diff_test_data_t *data=malloc(sizeof(diff_test_data_t));
	memset(data,0,sizeof(diff_test_data_t));
	mcs_cipher_t st0;
	mcs_cipher_init(&st0,key,nonce);
	mcs_cipher_xor_block(&st0,data->outst[0],data->outst[0],0);
	int idx=1;


	for(int i=0; i<64; i++){

		mcs_cipher_t st;
		copy_state(&st,&st0);
		st.a^=(((uint64_t)1)<<i);
		mcs_cipher_xor_block(&st,data->outst[idx],data->outst[idx],0);
		idx+=1;

	}

	for(int i=0; i<64; i++){

		mcs_cipher_t st;
		copy_state(&st,&st0);
		st.b^=(((uint64_t)1)<<i);
		mcs_cipher_xor_block(&st,data->outst[idx],data->outst[idx],0);
		idx+=1;

	}
	for(int i=0; i<64; i++){

		mcs_cipher_t st;
		copy_state(&st,&st0);
		st.c^=(((uint64_t)1)<<i);
		mcs_cipher_xor_block(&st,data->outst[idx],data->outst[idx],0);
		idx+=1;

	}

	for(int i=0; i<64; i++){

		mcs_cipher_t st;
		copy_state(&st,&st0);
		st.d^=(((uint64_t)1)<<i);
		mcs_cipher_xor_block(&st,data->outst[idx],data->outst[idx],0);
		idx+=1;

	}

	for(int i=0; i<64; i++){

		mcs_cipher_t st;
		copy_state(&st,&st0);
		st.e^=(((uint64_t)1)<<i);
		mcs_cipher_xor_block(&st,data->outst[idx],data->outst[idx],0);
		idx+=1;

	}

	for(int i=0; i<64; i++){

		mcs_cipher_t st;
		copy_state(&st,&st0);
		st.f^=(((uint64_t)1)<<i);
		mcs_cipher_xor_block(&st,data->outst[idx],data->outst[idx],0);
		idx+=1;

	}

	for(int i=0; i<64; i++){

		mcs_cipher_t st;
		copy_state(&st,&st0);
		st.g^=(((uint64_t)1)<<i);
		mcs_cipher_xor_block(&st,data->outst[idx],data->outst[idx],0);
		idx+=1;

	}

	for(int i=0; i<64; i++){

		mcs_cipher_t st;
		copy_state(&st,&st0);
		st.h^=(((uint64_t)1)<<i);
		mcs_cipher_xor_block(&st,data->outst[idx],data->outst[idx],0);
		idx+=1;

	}

	for(int i=0; i<64; i++){

		mcs_cipher_t st;
		copy_state(&st,&st0);
		st.i^=(((uint64_t)1)<<i);
		mcs_cipher_xor_block(&st,data->outst[idx],data->outst[idx],0);
		idx+=1;

	}

	for(int i=0; i<64; i++){

		mcs_cipher_t st;
		copy_state(&st,&st0);
		st.j^=(((uint64_t)1)<<i);
		mcs_cipher_xor_block(&st,data->outst[idx],data->outst[idx],0);
		idx+=1;

	}

	for(int i=0; i<64; i++){

		mcs_cipher_t st;
		copy_state(&st,&st0);
		st.k^=(((uint64_t)1)<<i);
		mcs_cipher_xor_block(&st,data->outst[idx],data->outst[idx],0);
		idx+=1;

	}

	for(int i=0; i<64; i++){

		mcs_cipher_t st;
		copy_state(&st,&st0);
		st.l^=(((uint64_t)1)<<i);
		mcs_cipher_xor_block(&st,data->outst[idx],data->outst[idx],0);
		idx+=1;

	}

	for(int i=0; i<64; i++){

		mcs_cipher_t st;
		copy_state(&st,&st0);
		st.m^=(((uint64_t)1)<<i);
		mcs_cipher_xor_block(&st,data->outst[idx],data->outst[idx],0);
		idx+=1;

	}

	for(int i=0; i<64; i++){

		mcs_cipher_t st;
		copy_state(&st,&st0);
		st.n^=(((uint64_t)1)<<i);
		mcs_cipher_xor_block(&st,data->outst[idx],data->outst[idx],0);
		idx+=1;

	}

	for(int i=0; i<64; i++){

		mcs_cipher_t st;
		copy_state(&st,&st0);
		st.o^=(((uint64_t)1)<<i);
		mcs_cipher_xor_block(&st,data->outst[idx],data->outst[idx],0);
		idx+=1;

	}

	for(int i=0; i<64; i++){

		mcs_cipher_t st;
		copy_state(&st,&st0);
		st.p^=(((uint64_t)1)<<i);
		mcs_cipher_xor_block(&st,data->outst[idx],data->outst[idx],0);
		idx+=1;

	}
	double total_comp=0;
	double sum_eq8=0;
	double sum_eq4=0;

	
	for(int i=0; i<idx; i++){
		for(int j=i+1; j<idx; j++){
			
			uint32_t lbeq=longest_bit_eq(data->outst[i],data->outst[j]);
			if(lbeq>=28){
				tinfo->exceed_limit_longest_bit_eq+=1;

			}
			if(lbeq>tinfo->longest_bit_eq){
				tinfo->longest_bit_eq=lbeq;

			}
			double eq=compare8(data->outst[i],data->outst[j]);
			if(eq==0){
				tinfo->full_diff8+=1;
			}
			sum_eq8+=eq;
			if(eq>tinfo->max_eq8){
				tinfo->max_eq8=eq;
			}
			if(eq>=0.024){
				tinfo->exceed_limit_eq8+=1;
			}
			eq=compare4(data->outst[i],data->outst[j]);
			if(eq==0){
				tinfo->full_diff4+=1;

			}
			sum_eq4+=eq;
			if(eq>tinfo->max_eq4){
				tinfo->max_eq4=eq;
			}
			if(eq>=0.1){
				tinfo->exceed_limit_eq4+=1;
			}


			total_comp+=1;

		}

	}
	
	tinfo->avg_eq8=sum_eq8/total_comp;
	tinfo->avg_eq4=sum_eq4/total_comp;

	for(int i=0; i<idx; i++){
		int l=0;
		for(int j=0; j<128; j++){
			uint8_t u8=data->outst[i][j];
			data->fq8[j][u8]+=1;
			uint8_t _u8=u8>>4;
			data->fq4[l][_u8]+=1;
			_u8=u8&0x0f;
			l+=1;
			data->fq4[l][_u8]+=1;
			l+=1;


		}

	}
	double total_block=(double)idx;

	
	for(int i=0; i<128; i++){
		for(int j=0; j<256; j++){
			uint32_t _fq=data->fq8[i][j];
			double fq=((double)_fq)/total_block;
			if(fq>=0.0078){
				tinfo->exceed_limit_fq8+=1;
			}
			if(fq>tinfo->max_fq8){
				tinfo->max_fq8=fq;
			}
		}
	}

	for(int i=0; i<256; i++){
		for(int j=0; j<16; j++){
			uint32_t _fq=data->fq4[i][j];
			double fq=((double)_fq)/total_block;
			if(fq>=0.072){
				tinfo->exceed_limit_fq4+=1;
			}
			if(fq>tinfo->max_fq4){
				tinfo->max_fq4=fq;
			}
		}
	}
	free(data);
}

uint32_t sigma_sum(uint32_t n){

	uint32_t ret=n-1;
	for(uint32_t i=ret-1; i>0; i--){

		ret+=i;
	}
	return ret;
}
int main(){
	test_info_t gtinfo;
	gtinfo.exceed_limit_fq8=0;
	gtinfo.exceed_limit_fq4=0;
	gtinfo.exceed_limit_eq8=0;
	gtinfo.exceed_limit_eq4=0;
	gtinfo.full_diff8=0;
	gtinfo.full_diff4=0;
	gtinfo.max_eq8=0;
	gtinfo.max_eq4=0;
	gtinfo.max_fq8=0;
	gtinfo.max_fq4=0;
	gtinfo.avg_eq8=0;
	gtinfo.avg_eq4=0;
	gtinfo.exceed_limit_longest_bit_eq=0;
	gtinfo.longest_bit_eq=0;
	uint8_t key[32];
	uint8_t nonce[32];
	double ttl_sample=50;
	//printf("%u\n",sigma_sum(1025));

	double ttl_subsample_comp=(double)sigma_sum(1025);
	

	for(double i=0; i<ttl_sample; i+=1){
		assert(getrandom(key,32,GRND_RANDOM)==32);
		assert(getrandom(nonce,32,GRND_RANDOM)==32);
		test_info_t tinfo;
		diff_test(key,nonce,&tinfo);
		gtinfo.exceed_limit_fq8+=tinfo.exceed_limit_fq8;
		gtinfo.exceed_limit_fq4+=tinfo.exceed_limit_fq4;
		gtinfo.exceed_limit_eq8+=tinfo.exceed_limit_eq8;
		gtinfo.exceed_limit_eq4+=tinfo.exceed_limit_eq4;
		gtinfo.full_diff8+=tinfo.full_diff8;
		gtinfo.full_diff4+=tinfo.full_diff4;
		if(tinfo.max_fq8>gtinfo.max_fq8){
			gtinfo.max_fq8=tinfo.max_fq8;
		}
		if(tinfo.max_fq4>gtinfo.max_fq4){
			gtinfo.max_fq4=tinfo.max_fq4;
		}
		if(tinfo.max_eq8>gtinfo.max_eq8){
			gtinfo.max_eq8=tinfo.max_eq8;

		}
		if(tinfo.max_eq4>gtinfo.max_eq4){
			gtinfo.max_eq4=tinfo.max_eq4;

		}
		gtinfo.exceed_limit_longest_bit_eq+=tinfo.exceed_limit_longest_bit_eq;
		gtinfo.avg_eq8+=tinfo.avg_eq8;
		gtinfo.avg_eq4+=tinfo.avg_eq4;
		if(tinfo.longest_bit_eq>gtinfo.longest_bit_eq){
			gtinfo.longest_bit_eq=tinfo.longest_bit_eq;
		}


		


		
	}
	gtinfo.avg_eq8/=ttl_sample;
	gtinfo.avg_eq4/=ttl_sample;
	printf("exceed limit freq 8bit : %u (%.2f%%)\n",
			gtinfo.exceed_limit_fq8,
			(((double)gtinfo.exceed_limit_fq8)/(ttl_sample*128*256))*100);
	printf("exceed limit freq 4bit : %u (%.2f%%)\n",
			gtinfo.exceed_limit_fq4,
			(((double)gtinfo.exceed_limit_fq4)/(ttl_sample*256*16))*100);
	printf("exceed limit equal 8bit: %u (%.2f%%)\n",
			gtinfo.exceed_limit_eq8,
			(((double)gtinfo.exceed_limit_eq8)/(ttl_sample*ttl_subsample_comp))*100);
	printf("exceed limit equal 4bit: %u (%.2f%%)\n",
			gtinfo.exceed_limit_eq4,
			(((double)gtinfo.exceed_limit_eq4)/(ttl_sample*ttl_subsample_comp))*100);
	printf("full diff 8bit         : %u (%.2f%%)\n",
			gtinfo.full_diff8,
			(((double)gtinfo.full_diff8)/(ttl_sample*ttl_subsample_comp))*100);
	printf("full diff 4bit         : %u\n",gtinfo.full_diff4);
	printf("max equal 8bit         : %.2f%%\n",gtinfo.max_eq8*100);
	printf("max equal 4bit         : %.2f%%\n",gtinfo.max_eq4*100);
	printf("max freq 8bit          : %.2f%%\n",gtinfo.max_fq8*100);
	printf("max freq 4bit          : %.2f%%\n",gtinfo.max_fq4*100);
	printf("avg equal 8bit         : %.2f%%\n",gtinfo.avg_eq8*100);
	printf("avg equal 4bit         : %.2f%%\n",gtinfo.avg_eq4*100);
	printf("exceed limit L bit eq  : %u\n",gtinfo.exceed_limit_longest_bit_eq);
	printf("longest bit equal      : %u\n",gtinfo.longest_bit_eq);


	

}
