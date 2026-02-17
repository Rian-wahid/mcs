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
#include<assert.h>
#include<linux/random.h>
#include<malloc.h>
#include<string.h>
#include<mcs_cipher.h>


typedef struct{
	uint64_t exceed_limit_fqg8;
	uint64_t exceed_limit_fqg4;
	uint64_t exceed_limit_fqb8;
	uint64_t exceed_limit_fqb4;
	uint64_t exceed_limit_fqp8;
	uint64_t exceed_limit_fqp4;
	double max_fqg8;
	double max_fqg4;
	double max_fqb8;
	double max_fqb4;
	double max_fqp8;
	double max_fqp4;
}test_info_t;

typedef struct{

	uint32_t fqg8[256];
	uint32_t fqg4[16];
	uint32_t fqb8[256];
	uint32_t fqb4[16];
	uint32_t fqp8[128][256];
	uint32_t fqp4[256][16];
}freq_data_t;
extern ssize_t getrandom(void *buf,size_t size,unsigned int flags);
void clean_fqb(freq_data_t *fq){

	memset(fq->fqb8,0,sizeof(fq->fqb8));
	memset(fq->fqb4,0,sizeof(fq->fqb4));

}

void clean_fqp(freq_data_t *fq){

	memset(fq->fqp8,0,sizeof(fq->fqp8));
	memset(fq->fqp4,0,sizeof(fq->fqp4));
}

void clean_fqg(freq_data_t *fq){

	memset(fq->fqg8,0,sizeof(fq->fqg8));
	memset(fq->fqg4,0,sizeof(fq->fqg4));
}
void clean_tinfo(test_info_t *tinfo){

	tinfo->exceed_limit_fqg8=0;
	tinfo->exceed_limit_fqg4=0;
	tinfo->exceed_limit_fqb8=0;
	tinfo->exceed_limit_fqb4=0;
	tinfo->exceed_limit_fqp8=0;
	tinfo->exceed_limit_fqp4=0;
	tinfo->max_fqg8=0;
	tinfo->max_fqg4=0;
	tinfo->max_fqb8=0;
	tinfo->max_fqb4=0;
	tinfo->max_fqp8=0;
	tinfo->max_fqp4=0;
}

void freq_test(
		uint8_t *key,
		uint8_t *nonce,
		test_info_t *tinfo128,
		test_info_t *tinfo1024,
		test_info_t *tinfo8192){
	clean_tinfo(tinfo128);
	clean_tinfo(tinfo1024);
	clean_tinfo(tinfo8192);
	freq_data_t *fq128=malloc(sizeof(freq_data_t));
	freq_data_t *fq1024=malloc(sizeof(freq_data_t));
	freq_data_t *fq8192=malloc(sizeof(freq_data_t));
	clean_fqb(fq128);
	

	clean_fqg(fq128);
	clean_fqg(fq1024);
	clean_fqg(fq8192);

	clean_fqp(fq128);
	clean_fqp(fq1024);
	clean_fqp(fq8192);

	mcs_cipher_t cpr;
	mcs_cipher_init(&cpr,key,nonce);
	for(uint64_t i=0; i<8192; i++){
		uint8_t outs[128];
		memset(outs,0,128);
		mcs_cipher_xor_block(&cpr,outs,outs,i);
		int l=0;
		for(int j=0; j<128; j++){

			uint8_t u8=outs[j];
			fq128->fqb8[u8]+=1;
			fq128->fqg8[u8]+=1;
			fq128->fqp8[j][u8]+=1;
			fq1024->fqg8[u8]+=1;
			fq1024->fqp8[j][u8]+=1;
			fq8192->fqg8[u8]+=1;
			fq8192->fqp8[j][u8]+=1;
			uint8_t u4=u8>>4;
			fq128->fqb4[u4]+=1;
			fq128->fqg4[u4]+=1;
			fq128->fqp4[l][u4]+=1;
			fq1024->fqg4[u4]+=1;
			fq1024->fqp4[l][u4]+=1;
			fq8192->fqg4[u4]+=1;
			fq8192->fqp4[l][u4]+=1;
			l+=1;
			u4=u8&0x0f;
			fq128->fqb4[u4]+=1;
			fq128->fqg4[u4]+=1;
			fq1024->fqg4[u4]+=1;
			fq8192->fqg4[u4]+=1;
			fq128->fqp4[l][u4]+=1;
			fq1024->fqp4[l][u4]+=1;
			fq8192->fqp4[l][u4]+=1;

			l+=1;

		}


		for(int j=0; j<256; j++){
			uint32_t _fq=fq128->fqb8[j];
			double fq=((double)_fq)/128;
			if(fq>tinfo128->max_fqb8){
				tinfo128->max_fqb8=fq;
			}
			if(fq>=0.06){
				tinfo128->exceed_limit_fqb8+=1;
			}

		}
		for(int j=0; j<16; j++){
			uint32_t _fq=fq128->fqb4[j];
			double fq=((double)_fq)/256;
			if(fq>tinfo128->max_fqb4){
				tinfo128->max_fqb4=fq;
			}
			if(fq>=0.12){

				tinfo128->exceed_limit_fqb4+=1;
			}

		}
		clean_fqb(fq128);
		if(i%128==0&&i!=0){
			for(int j=0; j<256; j++){
				uint32_t _fq=fq128->fqg8[j];
				double fq=((double)_fq)/(128*128);
				if(fq>tinfo128->max_fqg8){
					tinfo128->max_fqg8=fq;
				}
				if(fq>=0.006){
					tinfo128->exceed_limit_fqg8+=1;
				}


			}
			for(int j=0; j<16; j++){
				uint32_t _fq=fq128->fqg4[j];
				double fq=((double)_fq)/(256*128);
				if(fq>tinfo128->max_fqg4){
					tinfo128->max_fqg4=fq;
				}
				if(fq>=0.066){
					tinfo128->exceed_limit_fqg4+=1;
				}

			}

			for(int j=0; j<128; j++){
				for(int l=0; l<256; l++){
					uint32_t _fq=fq128->fqp8[j][l];
					double fq=((double)_fq)/128;
					if(fq>tinfo128->max_fqp8){
						tinfo128->max_fqp8=fq;
					}
					if(fq>=0.0625){
						tinfo128->exceed_limit_fqp8+=1;
					}
				}

			}
			for(int j=0; j<256; j++){
				for(int l=0; l<16; l++){
					uint32_t _fq=fq128->fqp4[j][l];
					double fq=((double)_fq)/128;
					if(fq>=0.16){
						tinfo128->exceed_limit_fqp4+=1;

					}
					if(fq>tinfo128->max_fqp4){
						tinfo128->max_fqp4=fq;

					}

				}

			}
			clean_fqg(fq128);
			clean_fqp(fq128);

		}
		
		if(i%1024==0&&i!=0){

			for(int j=0; j<256; j++){
				uint32_t _fq=fq1024->fqg8[j];
				double fq=((double)_fq)/(128*1024);
				if(fq>tinfo1024->max_fqg8){
					tinfo1024->max_fqg8=fq;
				}
				if(fq>=0.0045){
					tinfo1024->exceed_limit_fqg8+=1;
				}


			}
			for(int j=0; j<16; j++){
				uint32_t _fq=fq1024->fqg4[j];
				double fq=((double)_fq)/(256*1024);
				if(fq>tinfo1024->max_fqg4){
					tinfo1024->max_fqg4=fq;
				}
				if(fq>=0.063){
					tinfo1024->exceed_limit_fqg4+=1;
				}

			}

			for(int j=0; j<128; j++){
				for(int l=0; l<256; l++){
					uint32_t _fq=fq1024->fqp8[j][l];
					double fq=((double)_fq)/1024;
					if(fq>tinfo1024->max_fqp8){
						tinfo1024->max_fqp8=fq;
					}
					if(fq>=0.012){
						tinfo1024->exceed_limit_fqp8+=1;
					}
				}

			}
			for(int j=0; j<256; j++){
				for(int l=0; l<16; l++){
					uint32_t _fq=fq1024->fqp4[j][l];
					double fq=((double)_fq)/1024;
					if(fq>=0.09){
						tinfo1024->exceed_limit_fqp4+=1;

					}
					if(fq>tinfo1024->max_fqp4){
						
						tinfo1024->max_fqp4=fq;

					}

				}

			}
			clean_fqg(fq1024);
			clean_fqp(fq1024);
		}
	}

	for(int i=0; i<256; i++){

		uint32_t _fq=fq8192->fqg8[i];
		double fq=((double)_fq)/(128*8192);
		if(fq>tinfo8192->max_fqg8){
			tinfo8192->max_fqg8=fq;
		}
		if(fq>=0.004){
			tinfo8192->exceed_limit_fqg8+=1;
		}

	}
	for(int i=0; i<16; i++){

		uint32_t _fq=fq8192->fqg4[i];
		double fq=((double)_fq)/(256*8192);
		if(fq>tinfo8192->max_fqg4){
			tinfo8192->max_fqg4=fq;
		}
		if(fq>0.0625){
			tinfo8192->exceed_limit_fqg4+=1;
		}
	}

	for(int i=0; i<128; i++){

		for(int j=0; j<256; j++){
			uint32_t _fq=fq8192->fqp8[i][j];
			double fq=((double)_fq)/8192;
			if(fq>tinfo8192->max_fqp8){
				tinfo8192->max_fqp8=fq;
			}
			if(fq>=0.006){

				tinfo8192->exceed_limit_fqp8+=1;

			}

		}

	}
	
	for(int i=0; i<256; i++){

		for(int j=0; j<16; j++){
			uint32_t _fq=fq8192->fqp4[i][j];
			double fq=((double)_fq)/8192;
			if(fq>tinfo8192->max_fqp4){
				tinfo8192->max_fqp4=fq;
			}
			if(fq>=0.068){
				tinfo8192->exceed_limit_fqp4+=1;

			}
			

		}
	}




	free(fq128);
	free(fq1024);
	free(fq8192);

}


int main(){
	test_info_t gtinfo128;
	test_info_t gtinfo1024;
	test_info_t gtinfo8192;
	clean_tinfo(&gtinfo128);
	clean_tinfo(&gtinfo1024);
	clean_tinfo(&gtinfo8192);
	uint8_t key[32];
	uint8_t nonce[32];
	test_info_t tinfo128;
	test_info_t tinfo1024;
	test_info_t tinfo8192;
	for(int i=0; i<200; i++){
		assert(getrandom(key,32,GRND_RANDOM)==32);
		assert(getrandom(nonce,32,GRND_RANDOM)==32);
		
		freq_test(key,nonce,&tinfo128,&tinfo1024,&tinfo8192);
		gtinfo128.exceed_limit_fqb8+=tinfo128.exceed_limit_fqb8;
		gtinfo128.exceed_limit_fqb4+=tinfo128.exceed_limit_fqb4;
		gtinfo128.exceed_limit_fqg8+=tinfo128.exceed_limit_fqg8;
		gtinfo128.exceed_limit_fqg4+=tinfo128.exceed_limit_fqg4;
		gtinfo128.exceed_limit_fqp8+=tinfo128.exceed_limit_fqp8;
		gtinfo128.exceed_limit_fqp4+=tinfo128.exceed_limit_fqp4;

		gtinfo1024.exceed_limit_fqg8+=tinfo1024.exceed_limit_fqg8;
		gtinfo1024.exceed_limit_fqg4+=tinfo1024.exceed_limit_fqg4;
		gtinfo1024.exceed_limit_fqp8+=tinfo1024.exceed_limit_fqp8;
		gtinfo1024.exceed_limit_fqp4+=tinfo1024.exceed_limit_fqp4;

		gtinfo8192.exceed_limit_fqg8+=tinfo8192.exceed_limit_fqg8;
		gtinfo8192.exceed_limit_fqg4+=tinfo8192.exceed_limit_fqg4;
		gtinfo8192.exceed_limit_fqp8+=tinfo8192.exceed_limit_fqp8;
		gtinfo8192.exceed_limit_fqp4+=tinfo8192.exceed_limit_fqp4;

		if(tinfo128.max_fqb8>gtinfo128.max_fqb8){
			gtinfo128.max_fqb8=tinfo128.max_fqb8;
		}
		if(tinfo128.max_fqb4>gtinfo128.max_fqb4){
			gtinfo128.max_fqb4=tinfo128.max_fqb4;
		}
		if(tinfo128.max_fqg8>gtinfo128.max_fqg8){
			gtinfo128.max_fqg8=tinfo128.max_fqg8;
		}

		if(tinfo128.max_fqg4>gtinfo128.max_fqg4){
			gtinfo128.max_fqg4=tinfo128.max_fqg4;
		}

		if(tinfo128.max_fqp8>gtinfo128.max_fqp8){
			gtinfo128.max_fqp8=tinfo128.max_fqp8;
		}

		if(tinfo128.max_fqp4>gtinfo128.max_fqp4){
			gtinfo128.max_fqp4=tinfo128.max_fqp4;
		}


	
		if(tinfo1024.max_fqg8>gtinfo1024.max_fqg8){
			gtinfo1024.max_fqg8=tinfo1024.max_fqg8;
		}

		if(tinfo1024.max_fqg4>gtinfo1024.max_fqg4){
			gtinfo1024.max_fqg4=tinfo1024.max_fqg4;
		}

		if(tinfo1024.max_fqp8>gtinfo1024.max_fqp8){
			gtinfo1024.max_fqp8=tinfo1024.max_fqp8;
		}

		if(tinfo1024.max_fqp4>gtinfo1024.max_fqp4){
			gtinfo1024.max_fqp4=tinfo1024.max_fqp4;
		}


		if(tinfo8192.max_fqg8>gtinfo8192.max_fqg8){
			gtinfo8192.max_fqg8=tinfo8192.max_fqg8;
		}

		if(tinfo8192.max_fqg4>gtinfo8192.max_fqg4){
			gtinfo8192.max_fqg4=tinfo8192.max_fqg4;
		}

		if(tinfo8192.max_fqp8>gtinfo8192.max_fqp8){
			gtinfo8192.max_fqp8=tinfo8192.max_fqp8;
		}

		if(tinfo8192.max_fqp4>gtinfo8192.max_fqp4){
			gtinfo8192.max_fqp4=tinfo8192.max_fqp4;
		}
	
	}


	printf("limit fqb8      : %lu\n",gtinfo128.exceed_limit_fqb8);
	printf("limit fqb4      : %lu\n",gtinfo128.exceed_limit_fqb4);
	printf("limit fqg8 128  : %lu\n",gtinfo128.exceed_limit_fqg8);
	printf("limit fqg4 128  : %lu\n",gtinfo128.exceed_limit_fqg4);
	printf("limit fqp8 128	: %lu\n",gtinfo128.exceed_limit_fqp8);
	printf("limit fqp4 128	: %lu\n",gtinfo128.exceed_limit_fqp4);

	printf("limit fqg8 1024 : %lu\n",gtinfo1024.exceed_limit_fqg8);
	printf("limit fqg4 1024 : %lu\n",gtinfo1024.exceed_limit_fqg4);
	printf("limit fqp8 1024	: %lu\n",gtinfo1024.exceed_limit_fqp8);
	printf("limit fqp4 1024	: %lu\n",gtinfo1024.exceed_limit_fqp4);

	printf("limit fqg8 8192 : %lu\n",gtinfo8192.exceed_limit_fqg8);
	printf("limit fqg4 8192 : %lu\n",gtinfo8192.exceed_limit_fqg4);
	printf("limit fqp8 8192 : %lu\n",gtinfo8192.exceed_limit_fqp8);
	printf("limit fqp4 8192	: %lu\n",gtinfo8192.exceed_limit_fqp4);


	printf("max fqb8        : %.2f%%\n",gtinfo128.max_fqb8*100);
	printf("max fqb4        : %.2f%%\n",gtinfo128.max_fqb4*100);
	printf("max fqg8 128    : %.2f%%\n",gtinfo128.max_fqg8*100);
	printf("max fqg4 128    : %.2f%%\n",gtinfo128.max_fqg4*100);
	printf("max fqp8 128	: %.2f%%\n",gtinfo128.max_fqp8*100);
	printf("max fqp4 128	: %.2f%%\n",gtinfo128.max_fqp4*100);

	printf("max fqg8 1024   : %.2f%%\n",gtinfo1024.max_fqg8*100);
	printf("max fqg4 1024   : %.2f%%\n",gtinfo1024.max_fqg4*100);
	printf("max fqp8 1024   : %.2f%%\n",gtinfo1024.max_fqp8*100);
	printf("max fqp4 1024	: %.2f%%\n",gtinfo1024.max_fqp4*100);

	printf("max fqg8 8192   : %.2f%%\n",gtinfo8192.max_fqg8*100);
	printf("max fqg4 8182   : %.2f%%\n",gtinfo8192.max_fqg4*100);
	printf("max fqp8 8192   : %.2f%%\n",gtinfo8192.max_fqp8*100);
	printf("max fqp4 8192	: %.2f%%\n",gtinfo8192.max_fqp4*100);

}
