/**
 * @file rsa3072.c
 * @brief Minimal RSA 3072 Signature Verification
 *
 * RSA-SHA256 signature verification with PKCS#1 v1.5 padding.
 * Size-optimized implementation for embedded systems.
 *
 * @note Uses constant-time comparison to prevent timing attacks
 * @note Clears all sensitive data from stack before returning
 */

#include "rsa3072.h"
#include "bn384.h"
#include "sha256.h"
#include <string.h>


/*============================================================================*/
/* Constants                                                                  */
/*============================================================================*/

/**
 * @brief DigestInfo for SHA-256 (DER encoded, 19 bytes)
 *
 * ASN.1 structure:
 * SEQUENCE {
 *   SEQUENCE {
 *     OID 2.16.840.1.101.3.4.2.1 (SHA-256)
 *     NULL
 *   }
 *   OCTET STRING (32 bytes hash follows)
 * }
 *
 * This is prepended to the hash in PKCS#1 v1.5 padding.
 */
static const uint8_t SHA256_DIGEST_INFO[19] = {
    0x30, 0x31,                         /* SEQUENCE, 49 bytes total */
    0x30, 0x0D,                         /* SEQUENCE, 13 bytes (AlgorithmIdentifier) */
    0x06, 0x09,                         /* OID, 9 bytes */
    0x60, 0x86, 0x48, 0x01, 0x65,       /* 2.16.840.1.101.3.4.2.1 (SHA-256) */
    0x03, 0x04, 0x02, 0x01,
    0x05, 0x00,                         /* NULL */
    0x04, 0x20                          /* OCTET STRING, 32 bytes (hash follows) */
};

/**
 * @def DIGEST_INFO_LEN
 * @brief Length of DigestInfo structure in bytes
 */
#define DIGEST_INFO_LEN     19

/**
 * @def HASH_LEN
 * @brief Length of SHA-256 hash in bytes
 */
#define HASH_LEN            32

/**
 * @def PADDING_START
 * @brief Start position of 0xFF padding bytes in PKCS#1 v1.5 structure
 */
#define PADDING_START       2

/**
 * @def PADDING_END
 * @brief End position of 0xFF padding (position of 0x00 delimiter)
 *
 * For RSA 3072 (384 bytes): 384 - 19 - 32 - 1 = 332
 * Padding bytes are at positions 2 to 331 (330 bytes of 0xFF)
 */
#define PADDING_END         (RSA3072_KEY_BYTES - DIGEST_INFO_LEN - HASH_LEN - 1)


/*============================================================================*/
/* Internal Functions                                                         */
/*============================================================================*/

/**
 * @brief Secure memory clearing (prevents compiler optimization)
 *
 * Clears sensitive data from memory in a way that cannot be optimized
 * away by the compiler.
 *
 * @param[out] ptr  Pointer to memory to clear
 * @param[in]  len  Number of bytes to clear
 *
 * WHY THIS IMPLEMENTATION:
 * ========================
 *
 * PROBLEM WITH STANDARD memset():
 * When the compiler sees:
 *     memset(secret_data, 0, sizeof(secret_data));
 *     return result;  // secret_data is never used again
 *
 * The compiler may optimize away the memset() because:
 * - Dead store elimination: the cleared memory is never read
 * - The compiler doesn't understand security implications
 * - This is legal per the C standard (as-if rule)
 *
 * REAL-WORLD IMPACT:
 * - GCC with -O2 or -O3 often removes "useless" memset
 * - Sensitive data (keys, hashes, intermediate values) remains in memory
 * - Attacker can extract secrets via:
 *   - Memory dumps (cold boot attacks)
 *   - Buffer overflows reading adjacent memory
 *   - Core dumps / crash reports
 *   - Memory forensics
 *
 * SOLUTION: VOLATILE POINTER
 * Using a volatile pointer forces the compiler to:
 * 1. Actually perform each memory write
 * 2. Not assume the memory contents are predictable
 * 3. Not reorder or eliminate the writes
 *
 * The 'volatile' keyword tells the compiler:
 * "This memory location may be accessed by something outside
 *  the compiler's knowledge, so every access must be performed."
 *
 * WHY NOT OTHER SOLUTIONS:
 * - memset_s(): Not available on all platforms (C11 Annex K)
 * - explicit_bzero(): Not portable (BSD/glibc extension)
 * - SecureZeroMemory(): Windows-only
 * - Compiler barriers: Platform-specific, less portable
 *
 * The volatile pointer approach is:
 * - Portable to all C compilers
 * - Works with any optimization level
 * - No external dependencies
 * - Proven effective in cryptographic libraries (OpenSSL, libsodium)
 */
static void
secure_memzero                 (void*                   ptr,
                                size_t                  len)
{
    /*
     * Cast to volatile uint8_t pointer.
     *
     * 'volatile' qualifier on the POINTER means:
     * - Each dereference (*p) is a genuine memory access
     * - The compiler cannot assume *p has any particular value
     * - The compiler cannot skip any write to *p
     *
     * Note: 'volatile uint8_t* p' means "pointer to volatile uint8_t"
     *       NOT "volatile pointer to uint8_t"
     *
     * Each byte is written individually to ensure complete clearing
     * even if the compiler tries to optimize multi-byte operations.
     */
    volatile uint8_t*           p = (volatile uint8_t*)ptr;
    size_t                      i;

    for (i = 0; i < len; i++)
    {
        /*
         * This write CANNOT be optimized away because:
         * 1. p is a volatile pointer
         * 2. The compiler must assume something else might read *p
         * 3. Every iteration produces a real memory store instruction
         *
         * Assembly output will show actual store instructions
         * even at -O3 optimization level.
         */
        p[i] = 0;
    }
}


/**
 * @brief Constant-time memory comparison
 *
 * Compares two byte arrays in constant time to prevent timing attacks.
 * The entire arrays are always compared regardless of where differences occur.
 *
 * @param[in] a    First byte array
 * @param[in] b    Second byte array
 * @param[in] len  Number of bytes to compare
 *
 * @return 0 if arrays are equal, non-zero if different
 *
 * @note This function does NOT short-circuit on first difference
 */
static int
ct_memcmp                      (const uint8_t*          a,
                                const uint8_t*          b,
                                size_t                  len)
{
    size_t                      i;
    uint8_t                     diff;

    diff = 0;
    for (i = 0; i < len; i++)
    {
        diff |= a[i] ^ b[i];
    }

    return (int)diff;
}


/**
 * @brief Verify PKCS#1 v1.5 padding structure
 *
 * Expected structure for RSA 3072 (384 bytes):
 * @verbatim
 * Byte Position | Content
 * --------------|------------------
 * 0             | 0x00
 * 1             | 0x01 (block type)
 * 2 to 331      | 0xFF (padding, 330 bytes)
 * 332           | 0x00 (delimiter)
 * 333 to 351    | DigestInfo (19 bytes)
 * 352 to 383    | SHA-256 hash (32 bytes)
 * @endverbatim
 *
 * @param[in] decrypted  Decrypted signature (384 bytes)
 * @param[in] hash       Expected SHA-256 hash (32 bytes)
 *
 * @return RSA3072_OK if padding and hash are valid
 * @return RSA3072_ERR_VERIFY if verification failed
 *
 * @note Uses constant-time operations throughout
 */
static int
pkcs1_v15_verify               (const uint8_t*          decrypted,
                                const uint8_t*          hash)
{
    int                         i;
    uint8_t                     fail;

    fail = 0;

    /* Check header: must be 0x00 0x01 */
    fail |= decrypted[0] ^ 0x00;
    fail |= decrypted[1] ^ 0x01;

    /* Check padding bytes: all must be 0xFF
     * For RSA 3072: positions 2 to 331 (330 bytes) */
    for (i = PADDING_START; i < PADDING_END; i++)
    {
        fail |= decrypted[i] ^ 0xFF;
    }

    /* Check delimiter: must be 0x00 */
    fail |= decrypted[PADDING_END] ^ 0x00;

    /* Check DigestInfo: must match SHA-256 OID structure */
    fail |= (uint8_t)ct_memcmp(&decrypted[PADDING_END + 1],
                               SHA256_DIGEST_INFO,
                               DIGEST_INFO_LEN);

    /* Check hash: must match computed hash (constant-time) */
    fail |= (uint8_t)ct_memcmp(&decrypted[PADDING_END + 1 + DIGEST_INFO_LEN],
                               hash,
                               HASH_LEN);

    return (fail != 0) ? RSA3072_ERR_VERIFY : RSA3072_OK;
}


/*============================================================================*/
/* Public API                                                                 */
/*============================================================================*/

int
rsa3072_verify                 (const uint8_t*          p_public_n,
                                const uint8_t*          p_message,
                                size_t                  message_len,
                                const uint8_t*          p_signature)
{
    bn_mont_ctx                 ctx;
    bn384_t                     n;
    bn384_t                     sig;
    bn384_t                     decrypted_bn;
    uint8_t                     hash[SHA256_HASH_SIZE];
    uint8_t                     decrypted[RSA3072_KEY_BYTES];
    int                         ret;

    /* Step 0: Validate input parameters */
    if ((p_public_n == NULL) || (p_message == NULL) || (p_signature == NULL))
    {
        return RSA3072_ERR_PARAM;
    }

    /* Step 1: Compute SHA-256 hash of the message */
    sha256(p_message, message_len, hash);

    /* Step 2: Convert inputs from big-endian bytes to internal format */
    bn384_from_bytes(&n, p_public_n);
    bn384_from_bytes(&sig, p_signature);

    /* Step 3: Verify signature < N (required for valid RSA signature) */
    if (bn384_cmp(&sig, &n) >= 0)
    {
        return RSA3072_ERR_VERIFY;
    }

    /* Step 4: Initialize Montgomery context for modulus N
     * Precomputes R^2 mod N and -N^(-1) mod 2^32 */
    bn_mont_init(&ctx, &n);

    /* Step 5: Compute signature^65537 mod N (RSA public key operation)
     * Uses Montgomery multiplication for efficiency */
    bn_modexp_e65537(&decrypted_bn, &sig, &ctx);

    /* Step 6: Convert result back to big-endian byte array */
    bn384_to_bytes(decrypted, &decrypted_bn);

    /* Step 7: Verify PKCS#1 v1.5 padding and compare hash */
    ret = pkcs1_v15_verify(decrypted, hash);

    /*
     * Step 8: Clear all sensitive data from stack
     *
     * SECURITY-CRITICAL: Using secure_memzero() instead of memset()
     *
     * WHY THIS MATTERS:
     * The variables being cleared contain cryptographically sensitive data:
     *
     * 1. ctx (bn_mont_ctx):
     *    - Contains modulus N and precomputed Montgomery constants
     *    - Could help attacker factor N or perform other attacks
     *
     * 2. sig (bn384_t):
     *    - The signature being verified
     *    - Not secret per se, but clearing prevents confusion with other data
     *
     * 3. decrypted_bn (bn384_t):
     *    - Result of sig^e mod N
     *    - Contains the decrypted PKCS#1 structure
     *
     * 4. hash (32 bytes):
     *    - SHA-256 hash of the message
     *    - Could be used in length extension or other attacks
     *
     * 5. decrypted (384 bytes):
     *    - Byte representation of decrypted_bn
     *    - Contains full PKCS#1 v1.5 structure with hash
     *
     * If we used regular memset(), the compiler might optimize it away
     * since these variables are never read after this point.
     * secure_memzero() guarantees the clearing actually happens.
     *
     * ATTACK SCENARIO PREVENTED:
     * Without proper clearing, an attacker could:
     * - Trigger a buffer overflow in later code to read this stack area
     * - Cause a crash and examine core dump
     * - Use cold boot attack to read RAM contents
     * - Exploit another vulnerability to scan stack memory
     */
    secure_memzero(&ctx, sizeof(ctx));
    secure_memzero(&sig, sizeof(sig));
    secure_memzero(&decrypted_bn, sizeof(decrypted_bn));
    secure_memzero(hash, sizeof(hash));
    secure_memzero(decrypted, sizeof(decrypted));

    return ret;
}
