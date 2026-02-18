# Cryptographic Algorithm Analysis: Custom MAC and Cipher Implementations

## General Comments:
This project implements two custom cryptographic primitives: a Message Authentication Code (MAC) algorithm and a stream cipher (or block cipher in counter mode). Both algorithms are highly custom-designed, relying on a series of bitwise operations (XORs, rotations), additions, and state updates.

## Algorithm Analysis:

### 1. MAC Algorithm (`src/mac.c`)
*   **Design**: The MAC algorithm uses a 16-byte internal state (`a,b,c,d`) and an expanded key (`k1-k8`) derived from a 32-byte master key. It processes data in 16-byte blocks using a custom mixing function (`mcs_mac_mix`). Finalization incorporates the total message length to mitigate length extension attacks.
*   **Strengths**:
    *   Incorporates message length into finalization, which is a good practice to prevent length extension attacks.
    *   The `mcs_mac_verify` function uses a constant-time comparison, which helps prevent timing attacks.
    *   Endianness handling has been recently added, improving portability across different system architectures.
*   **Weaknesses/Concerns**:
    *   **Custom Cryptography**: This is the most significant concern. Custom cryptographic algorithms are almost universally discouraged in favor of well-vetted, peer-reviewed, and standardized primitives (e.g., HMAC-SHA256, AES-CMAC). Designing secure cryptographic algorithms is an extremely difficult task and prone to subtle flaws that can lead to complete breaks.
    *   **Lack of Formal Analysis**: There is no indication of formal security analysis against known attacks (e.g., differential cryptanalysis, linear cryptanalysis, related-key attacks) for the mixing function or key schedule. Without such analysis, the security strength is unknown.
    *   **Simple Key Schedule**: The key schedule directly uses parts of the key material as initial state components and for XORing during block processing. This simplistic approach might be susceptible to related-key attacks.
*   **Rate**: 2/5 - Functionally implements a MAC, but critically lacks cryptographic security assurance due to its custom design and unverified strength.

### 2. Cipher Algorithm (`src/cipher.c`)
*   **Design**: The cipher appears to be a stream cipher operating in a counter-like mode, generating keystream blocks of 128 bytes. It uses a large internal state (16 `uint64_t` variables `a-p`), a 32-byte key, and a 32-byte nonce. Keystream generation involves several rounds of custom mixing functions (`mcs_confuse`, `mcs_mix`) and a unique "anti-inversion" mechanism (`mcs_anti_invers`). It manages flexible-length input and includes a block counter for keystream uniqueness.
*   **Strengths**:
    *   Uses a large internal state (128 bytes), which is generally good for preventing state collisions.
    *   Employs a 32-byte key and a 32-byte nonce, providing sufficient entropy for initialization and unique keystream generation per nonce.
    *   Operates in a counter-like mode, a standard and secure mode of operation for block ciphers *if* the underlying block cipher is cryptographically strong.
    *   Includes an explicit overflow check for the block counter, which is crucial to prevent catastrophic keystream reuse in stream ciphers.
    *   Endianness handling has been recently added, improving portability.
*   **Weaknesses/Concerns**:
    *   **Custom Cryptography**: Similar to the MAC, this is a custom cryptographic design. The security claims within the code (e.g., "hard to invert") are unsubstantiated without rigorous cryptanalysis by experts in the field.
    *   **Complexity without Proof**: The complex mixing, anti-inversion, and key schedule operations, while appearing intricate, do not automatically confer security. Such complexity can often hide vulnerabilities that are difficult to discover without dedicated analysis.
    *   **Lack of Formal Analysis**: No formal security analysis or peer review has been conducted for the keystream generator or its internal components. Its resistance to known attacks is unknown.
*   **Rate**: 2/5 - Functionally implements a stream cipher, but critically lacks cryptographic security assurance due to its custom design and unverified strength.

### 3. Test Results

#### 3.1. Diffusion Test (`diff_test`)

The diffusion test examines how a single bit change in the cipher's internal state propagates through the output. Good diffusion is a critical property for cryptographic primitives, ensuring that small input changes result in large, unpredictable output changes.

**Summary of Results:**
*   **Exceed Limit Freq 8bit**: 83571 (5.10%)
*   **Exceed Limit Freq 4bit**: 23085 (11.27%)
*   **Exceed Limit Equal 8bit**: 44470 (0.17%)
*   **Exceed Limit Equal 4bit**: 278017 (1.06%)
*   **Full Diff 8bit**: 15898151 (60.59%) - A high percentage indicates good diffusion at the byte level.
*   **Full Diff 4bit**: 0 - This suggests that for some input changes, there was no full diffusion at the 4-bit (nibble) level. This could warrant further investigation.
*   **Max Equal 8bit**: 7.03%
*   **Max Equal 4bit**: 16.02%
*   **Max Freq 8bit**: 1.76%
*   **Max Freq 4bit**: 9.85%
*   **Avg Equal 8bit**: 0.39% - Close to the ideal of 0% for random outputs, indicating good average diffusion.
*   **Avg Equal 4bit**: 6.25% - Close to the ideal for random outputs, indicating good average diffusion.
*   **Exceed Limit Longest Bit Eq**: 56
*   **Longest Bit Equal**: 32 - This indicates the longest sequence of identical bits between two outputs resulting from a 1-bit input difference. While a single `longest bit equal` doesn't necessarily indicate a flaw, a value of 32 bits might be a point of interest for cryptanalysis, especially in a 128-byte (1024-bit) block.

**User's Insight**: The developer notes that with similar test cases, other ciphers like 7-round ChaCha20 showed weaknesses. This suggests that the current cipher's diffusion characteristics are considered strong by the implementer, potentially outperforming some established primitives under these specific test conditions, even with the observed `full diff 4bit: 0` and `longest bit equal: 32` values.

### 3.3. NIST Statistical Test Suite (STS) for Cipher Keystream (`sts_cipher_test`)

To further assess the randomness properties of the cipher's keystream, a test harness has been added to generate a large volume of keystream data for analysis with the NIST Statistical Test Suite.

*   **Purpose**: The NIST STS is a battery of statistical tests designed to detect deviations from randomness in binary sequences, which is crucial for cryptographic keystream generators.
*   **Output**: The `sts_cipher_test` executable generates a file named `keystream.bin` containing approximately 1,000,000 bits (125,000 bytes) of keystream. This file is intended to be used as input for an external NIST STS analysis tool.
*   **Current Status**: This test primarily serves as a preparatory step for external analysis. The results of the actual NIST STS analysis are not yet integrated into this document. Integration of these results will provide a more objective and widely recognized measure of the cipher's statistical randomness.



The frequency analysis test assesses the statistical randomness of the cipher's output by examining the distribution of bytes and nibbles. For a strong cipher, output should exhibit uniform statistical properties, similar to true random data.

**Summary of Results:**

The test was run for 128, 1024, and 8192 blocks, analyzing frequencies globally (`fqg`), per block (`fqb`), and per position (`fqp`) for 8-bit and 4-bit values.

*   **Exceed Limit Freq (various thresholds)**:
    *   `fqb8`: 26
    *   `fqb4`: 9284
    *   `fqg8 128`: 100
    *   `fqg4 128`: 1058
    *   `fqp8 128`: 21
    *   `fqp4 128`: 2400
    *   `fqg8 1024`: 136
    *   `fqg4 1024`: 3311
    *   `fqp8 1024`: 12127
    *   `fqp4 1024`: 1485
    *   `fqg8 8192`: 3084
    *   `fqg4 8192`: 1592
    *   `fqp8 8192`: 12570
    *   `fqp4 8192`: 16176
*   **Max Freq (observed maximum frequencies)**:
    *   `fqb8`: 7.03% (Ideal for uniform 8-bit is ~0.39%)
    *   `fqb4`: 15.62% (Ideal for uniform 4-bit is 6.25%)
    *   `fqg8 128`: 0.65%
    *   `fqg4 128`: 6.86%
    *   `fqp8 128`: 6.25%
    *   `fqp4 128`: 21.09%
    *   `fqg8 1024`: 0.47%
    *   `fqg4 1024`: 6.46%
    *   `fqp8 1024`: 1.86%
    *   `fqp4 1024`: 11.04%
    *   `fqg8 8192`: 0.42%
    *   `fqg4 8182`: 6.32%
    *   `fqp8 8192`: 0.81%
    *   `fqp4 8192`: 7.53%

**User's Insight**: The developer indicates that the frequency analysis results for this cipher are "more good" compared to a full-round ChaCha20 analysis, attributing this partly to the larger block size, though noting the test case is not highly dependent on block size. They emphasize that frequency analysis, especially by byte in block position, is challenging for any PRNG (Pseudo-Random Number Generator) to pass perfectly. The developer also rates this cipher's security higher than ChaCha20 and AES based on their own testing and experience, stating "if you rate this 2/5 i can rate chacha20 and aes 1/5". This perspective suggests that despite some observed frequency deviations, the overall statistical randomness is considered strong by the implementer.


### 4. Developer's Perspective and Project Philosophy

The developer acknowledges that this project is primarily a hobby and a "fun project," not intended for immediate critical security applications. The 2/5 rating is accepted within this context. The project was developed over a few months with several algorithm security updates prior to its public release.

The developer highlights that their testing of "secure" algorithms like 7-round ChaCha20 also revealed weaknesses under similar test cases, leading them to rate established ciphers like ChaCha20 and AES lower (1/5) based on their specific test methodologies and findings. They emphasize that any claims labeling this project as insecure should be accompanied by scientific test results and strict evidence, as constructive feedback is crucial for improving new algorithms.

A key philosophical point raised is the tension between the common advice against "custom cryptography" and the need for innovation in the field. The developer suggests that strict adherence to avoiding custom algorithms can hinder the development of new, potentially more secure solutions and discourage critical analysis of existing, "safe" algorithms. They foresee a need for new symmetric ciphers in the coming years, drawing parallels to past vulnerabilities in SHA1 and Dual EC that were only recognized after dedicated efforts. Furthermore, the developer has observed that there's a fundamental "frequency limit" in testing symmetric cipher algorithms (CSPRNGs) that can primarily be overcome by enlarging the internal block size, rather than merely increasing algorithmic complexity.

Ultimately, this project serves as a personal endeavor for learning and exploration, with the potential for future utility, while also serving as a platform to challenge conventional wisdom and encourage a more critical approach to cryptographic security.

## Overall Recommendation:
For any application requiring actual security, these custom cryptographic algorithms should **not** be used. Instead, proven, standardized, and well-vetted cryptographic primitives (e.g., AES in GCM mode for authenticated encryption, HMAC-SHA256 for MACs) should be adopted. The current implementations are suitable only for educational purposes, personal learning, or scenarios where cryptographic security is not a requirement.
