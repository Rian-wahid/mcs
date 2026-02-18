#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "mcs_cipher.h"

#define KEYSTREAM_SIZE_BITS (1000000 * 1) // 1 million bits
#define KEYSTREAM_SIZE_BYTES (KEYSTREAM_SIZE_BITS / 8) // 125,000 bytes
#define BLOCK_SIZE_BYTES 128 // MCS cipher block size

void generate_keystream_file(const char *filename, uint64_t num_bytes) {
    mcs_cipher_t cipher;
    uint8_t key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                       0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    uint8_t nonce[32] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
                         0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    
    uint8_t keystream_block[BLOCK_SIZE_BYTES];
    uint8_t zero_block[BLOCK_SIZE_BYTES] = {0}; // Used to generate pure keystream

    FILE *fp = fopen(filename, "w");
    if (fp == NULL) {
        perror("Failed to open file for writing keystream");
        exit(EXIT_FAILURE);
    }

    mcs_cipher_init(&cipher, key, nonce);

    uint64_t bytes_generated = 0;
    while (bytes_generated < num_bytes) {
        mcs_cipher_xor_block(&cipher, keystream_block, zero_block, cipher.block_count);
        cipher.block_count++;

        size_t bytes_to_process = (num_bytes - bytes_generated < BLOCK_SIZE_BYTES) ? (num_bytes - bytes_generated) : BLOCK_SIZE_BYTES;
        for (size_t i = 0; i < bytes_to_process; ++i) {
            for (int j = 7; j >= 0; --j) { // Iterate through bits from MSB to LSB
                if (fputc(((keystream_block[i] >> j) & 1) ? '1' : '0', fp) == EOF) {
                    perror("Failed to write bit to file");
                    fclose(fp);
                    exit(EXIT_FAILURE);
                }
            }
        }
        bytes_generated += bytes_to_process;
    }

    fclose(fp);
    printf("Generated %lu bits of keystream to %s for NIST STS testing.\n", num_bytes * 8, filename);
}

int main() {
    generate_keystream_file("keystream.bin", KEYSTREAM_SIZE_BYTES);
    return 0;
}
