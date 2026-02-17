# Project Overview: MCS Cryptographic Library

## Abstract
The MCS Cryptographic Library (MCS) is a custom-designed cryptographic suite providing a stream cipher and a Message Authentication Code (MAC) algorithm. Developed for specific security requirements, this library offers fundamental cryptographic primitives for data confidentiality and integrity.

## 1. Introduction
The MCS library aims to provide lightweight, custom cryptographic solutions. It comprises a stream cipher for symmetric encryption/decryption and a MAC algorithm for ensuring message integrity and authenticity. This document details the design and operational principles of these core components.

## 2. Stream Cipher (MCS-Cipher)

### 2.1 Design Philosophy
The MCS stream cipher is built upon a custom permutation-based pseudorandom number generator (PRNG) that evolves a 256-bit internal state. Its design incorporates multiple rounds of mixing and confusion functions to generate a keystream. The keystream is then XORed with the plaintext to achieve encryption or with the ciphertext for decryption.

### 2.2 Key and Nonce Setup
The cipher is initialized using `mcs_cipher_init`, which takes a 32-byte (256-bit) key and a 32-byte (256-bit) nonce. The key and nonce are used to seed the initial 256-bit internal state (`a` through `p`) and to derive a separate "anti-inverse" key (`ka` through `kp`). The initialization process involves several applications of custom `mcs_confuse` and `mcs_anti_invers` functions to thoroughly mix the input entropy into the state.

### 2.3 Core Operations
The library provides two primary functions for data encryption/decryption:
- **`mcs_cipher_xor_block`**: This function operates on fixed 128-byte blocks of data. For each block, it incorporates a block counter into the internal state, then subjects the state to multiple rounds of `mcs_confuse` and `mcs_mix` functions. These functions perform bitwise XORs, cyclic rotations, and additions on 64-bit words to ensure rapid diffusion and confusion. After the state transformation, the "anti-inverse" key components are added to the state. The resulting 128-byte transformed state is then XORed with the input data block to produce the output.
- **`mcs_cipher_xor_stream`**: This function allows for encryption/decryption of data streams of arbitrary length. It internally manages the processing of full 128-byte blocks using `mcs_cipher_xor_block` and buffers any partial blocks to ensure continuous keystream application across calls.

### 2.4 Internal Functions
- **`mcs_confuse`**: A mixing function that takes four 64-bit words and applies a series of XORs, rotations, and additions to them.
- **`mcs_mix`**: Another mixing function, similar to `mcs_confuse`, but with different rotation and shift constants, applied multiple times within the keystream generation loop.
- **`mcs_anti_invers`**: A specialized function that applies a non-invertible transformation to four 64-bit words, used during initialization and potentially to enhance resistance against certain attacks.

### 2.5 Limitations and Considerations
- **Endianness**: The implementation now includes platform-specific adaptations for endianness, supporting little-endian systems (x86/x64 Windows, Linux, macOS, FreeBSD). This mitigates the previous assumption of a purely little-endian system for handling multi-byte values (e.g., `uint64_t` from `uint8_t*` arrays). Systems where endianness cannot be determined will default to little-endian.
- **Flexible-Length Input**: The `mcs_cipher_xor_stream` function is now fully implemented, allowing for encryption/decryption of data streams of arbitrary length. It handles buffering of partial blocks internally.
- **Counter Overflow**: The `mcs_cipher_xor_block` function includes a mechanism to detect and assert on counter overflow, ensuring the block counter does not wrap around during extended use.
- **Cryptographic Strength**: As a custom cipher, its cryptographic strength relies heavily on the design of `mcs_confuse`, `mcs_mix`, and `mcs_anti_invers`. Rigorous cryptanalysis would be required to ascertain its security against known attacks.

## 3. Message Authentication Code (MCS-MAC)

### 3.1 Design Philosophy
The MCS-MAC algorithm provides message integrity and authenticity. It processes input data in blocks, evolving an internal state based on the input and a secret key. A final tag is produced that can be used to verify if a message has been tampered with.

### 3.2 Key Setup
The MAC algorithm is initialized with `mcs_mac_init`, taking a 32-byte (256-bit) key. The key is divided into eight 32-bit words (`k1` through `k8`), which are used to seed the initial 128-bit internal state (`a`, `b`, `c`, `d`) and for mixing operations during processing.

### 3.3 Core Operations
- **`mcs_mac_write`**: This function processes input data of arbitrary length. It updates an internal 128-bit counter that tracks the total length of processed data and handles buffering for partial 16-byte blocks.
- **`mcs_mac_calc`**: Processes a 16-byte block of input data. It XORs the input with the current internal state, applies the `mcs_mac_mix` function, XORs with specific key parts (`k1` to `k4`), and applies `mcs_mac_mix` again to update the state.
- **`mcs_mac_digest`**: Finalizes the MAC calculation. It first calls `mcs_mac_calc_final`, which processes any remaining buffered data and incorporates the total message length and additional key material into the final state. The resulting 16-byte MAC tag is then outputted.
- **`mcs_mac_verify`**: Compares a newly computed MAC tag with a provided reference tag. The comparison is performed in a constant-time manner to mitigate timing attacks.

### 3.4 Internal Functions
- **`mcs_mac_mix`**: A mixing function for four 32-bit words, applying XORs, rotations, and additions to ensure state diffusion.

### 3.5 Limitations and Considerations
- **Endianness**: The implementation now includes platform-specific adaptations for endianness, supporting little-endian systems (x86/x64 Windows, Linux, macOS, FreeBSD) for handling multi-byte values. Systems where endianness cannot be determined will default to little-endian.
- **Flexible-Length Input Handling**: The `mcs_mac_write` function now fully supports arbitrary input lengths, correctly buffering partial blocks and updating internal length counters.
- **Cryptographic Strength**: The security of MCS-MAC depends on the `mcs_mac_mix` function and the key integration. It requires formal security analysis to validate its robustness.

## 4. Conclusion
The MCS Cryptographic Library provides custom implementations of a stream cipher and a MAC algorithm. While offering core cryptographic functionalities, it includes noted areas for further development, particularly concerning endianness portability and complete flexible-length input handling. Rigorous cryptanalysis and adherence to established cryptographic best practices are crucial for its deployment in security-critical applications.