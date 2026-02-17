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

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "mcs_mac.h" // Assuming mcs_mac.h is in the include directory

void mac_test_simple() {
    printf("Running simple MAC test...\n");

    uint8_t key[32];
    uint8_t msg[] = "Hello, world!";
    size_t msg_len = strlen((char*)msg);
    uint8_t mac_tag[16]; // Renamed to avoid confusion with context

    mcs_mac_t ctx; // Corrected type

    // Initialize key (simple static key for testing)
    for (int i = 0; i < 32; ++i) {
        key[i] = (uint8_t)i;
    }

    // --- Test 1: Generate and Verify a MAC ---
    mcs_mac_init(&ctx, key);
    mcs_mac_write(&ctx, msg, msg_len); // Corrected function name
    mcs_mac_digest(&ctx, mac_tag);     // Corrected function name

    printf("MAC generated successfully.\n");

    // To verify, we need a new context initialized with the same key
    mcs_mac_t verify_ctx;
    mcs_mac_init(&verify_ctx, key);
    mcs_mac_write(&verify_ctx, msg, msg_len); // Update with the same message

    if (mcs_mac_verify(&verify_ctx, mac_tag)) { // Corrected function call
        printf("Verification successful for correct MAC.\n");
    } else {
        printf("Verification FAILED for correct MAC.\n");
        assert(0 && "Correct MAC verification failed!");
    }

    // --- Test 2: Verify with a tampered message ---
    uint8_t tampered_msg[] = "Hello, World!"; // Different case
    size_t tampered_msg_len = strlen((char*)tampered_msg);

    mcs_mac_init(&verify_ctx, key); // Re-initialize context
    mcs_mac_write(&verify_ctx, tampered_msg, tampered_msg_len); // Update with tampered message

    if (!mcs_mac_verify(&verify_ctx, mac_tag)) { // Expected to fail
        printf("Verification successful for tampered message (expected to fail).\n");
    } else {
        printf("Verification FAILED for tampered message (expected to succeed).\n");
        assert(0 && "Tampered message verification passed unexpectedly!");
    }

    // --- Test 3: Generate a second MAC and verify ---
    uint8_t msg2[] = "Another message.";
    size_t msg2_len = strlen((char*)msg2);
    uint8_t mac_tag2[16];

    mcs_mac_init(&ctx, key);
    mcs_mac_write(&ctx, msg2, msg2_len);
    mcs_mac_digest(&ctx, mac_tag2);

    printf("Second MAC generated successfully.\n");

    mcs_mac_init(&verify_ctx, key); // Re-initialize context
    mcs_mac_write(&verify_ctx, msg2, msg2_len); // Update with second message

    if (mcs_mac_verify(&verify_ctx, mac_tag2)) {
        printf("Verification successful for second correct MAC.\n");
    } else {
        printf("Verification FAILED for second correct MAC.\n");
        assert(0 && "Second correct MAC verification failed!");
    }
    
    printf("Simple MAC test completed successfully.\n\n");
}

int main() {
    mac_test_simple();
    return 0;
}
