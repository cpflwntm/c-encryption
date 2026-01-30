/**
 * @file rsa3072.c
 * @brief Minimal RSA 3072 Signature Verification
 *
 * RSA-SHA256 signature verification with PKCS#1 v1.5 padding.
 * Size-optimized implementation for embedded systems.
 *
 * Includes integrated BigNum (3072-bit) arithmetic with Montgomery
 * multiplication. All internal operations use constant-time algorithms
 * to prevent timing side-channel attacks.
 *
 * @note Uses constant-time comparison to prevent timing attacks
 * @note Clears all sensitive data from stack before returning
 * @note No C library dependency (no memcpy/memset/string.h)
 */

#include "rsa3072.h"
#include "sha256.h"


/*============================================================================*/
/* BigNum Constants                                                           */
/*============================================================================*/

/**
 * @def BN_BYTES
 * @brief Size of RSA 3072 operands in bytes (3072 bits / 8)
 */
#define BN_BYTES    384

/**
 * @def BN_WORDS
 * @brief Size of RSA 3072 operands in 32-bit words (384 bytes / 4)
 */
#define BN_WORDS    96

/**
 * @def BN_BITS
 * @brief Size of RSA 3072 operands in bits
 */
#define BN_BITS     3072


/*============================================================================*/
/* BigNum Types                                                               */
/*============================================================================*/

/**
 * @typedef bn_word
 * @brief Single-precision word type (32-bit unsigned)
 */
typedef uint32_t bn_word;

/**
 * @typedef bn_dword
 * @brief Double-precision word type for intermediate calculations (64-bit unsigned)
 */
typedef uint64_t bn_dword;

/**
 * @struct bn384_t
 * @brief 384-byte (3072-bit) big number
 *
 * Stores a 3072-bit unsigned integer in little-endian word order.
 * d[0] is the least significant word, d[95] is the most significant word.
 */
typedef struct {
    bn_word d[BN_WORDS];    /**< Array of 32-bit words (little-endian order) */
} bn384_t;

/**
 * @struct bn_mont_ctx
 * @brief Montgomery multiplication context
 *
 * Precomputed values for efficient Montgomery modular multiplication.
 * Must be initialized with bn_mont_init() before use.
 *
 * R^2 mod N is computed on-the-fly during verification (not stored here)
 * to reduce context size from 772 to 388 bytes.
 */
typedef struct {
    bn384_t n;      /**< Modulus N */
    bn_word n0;     /**< -N^(-1) mod 2^32 (Montgomery constant) */
} bn_mont_ctx;


/*============================================================================*/
/* RSA Constants                                                              */
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
const uint8_t SHA256_DIGEST_INFO[19] = {
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
/* Internal Utility Functions                                                 */
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
    volatile uint8_t*           p = (volatile uint8_t*)ptr;
    size_t                      i;

    for (i = 0; i < len; i++)
    {
        p[i] = 0;
    }
}


/**
 * @brief Constant-time memory copy (prevents compiler optimization)
 *
 * Copies data from source to destination using volatile pointers to prevent
 * the compiler from optimizing away or reordering the copy operation.
 * Executes in constant time regardless of data content.
 *
 * @param[out] dst  Destination buffer
 * @param[in]  src  Source buffer
 * @param[in]  len  Number of bytes to copy
 *
 * WHY NOT STANDARD memcpy():
 * 1. C library dependency causes HardFault in swappable code sections
 *    (veneer calls may not be accessible from swapped iRAM region)
 * 2. Compiler may optimize or reorder memcpy in unexpected ways
 * 3. Self-contained implementation ensures no external symbol dependency
 */
static void
secure_memcpy                  (void*                   dst,
                                const void*             src,
                                size_t                  len)
{
    volatile uint8_t*           d = (volatile uint8_t*)dst;
    const volatile uint8_t*     s = (const volatile uint8_t*)src;
    size_t                      i;

    for (i = 0; i < len; i++)
    {
        d[i] = s[i];
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


/*============================================================================*/
/* BigNum Basic Operations                                                    */
/*============================================================================*/

/**
 * @brief Convert big-endian byte array to bn384_t
 *
 * Converts a 384-byte big-endian byte array to internal little-endian
 * word representation.
 *
 * @param[out] r      Pointer to destination bn384_t
 * @param[in]  bytes  Pointer to 384-byte big-endian input array
 */
void
bn384_from_bytes               (bn384_t*                r,
                                const uint8_t*          bytes)
{
    int                         i;
    int                         j;

    /* Convert big-endian bytes to little-endian words
     * bytes[0..3]   -> d[95] (MSW)
     * bytes[380..383] -> d[0]  (LSW) */
    for (i = 0; i < BN_WORDS; i++)
    {
        j = (BN_WORDS - 1 - i) * 4;
        r->d[i] = ((bn_word)bytes[j + 0] << 24) |
                  ((bn_word)bytes[j + 1] << 16) |
                  ((bn_word)bytes[j + 2] << 8)  |
                  ((bn_word)bytes[j + 3]);
    }
}


/**
 * @brief Convert bn384_t to big-endian byte array
 *
 * Converts internal little-endian word representation to a 384-byte
 * big-endian byte array.
 *
 * @param[out] bytes  Pointer to 384-byte output buffer
 * @param[in]  a      Pointer to source bn384_t
 */
void
bn384_to_bytes                 (uint8_t*                bytes,
                                const bn384_t*          a)
{
    int                         i;
    int                         j;

    /* Convert little-endian words to big-endian bytes
     * d[95] (MSW) -> bytes[0..3]
     * d[0]  (LSW) -> bytes[380..383] */
    for (i = 0; i < BN_WORDS; i++)
    {
        j = (BN_WORDS - 1 - i) * 4;
        bytes[j + 0] = (uint8_t)(a->d[i] >> 24);
        bytes[j + 1] = (uint8_t)(a->d[i] >> 16);
        bytes[j + 2] = (uint8_t)(a->d[i] >> 8);
        bytes[j + 3] = (uint8_t)(a->d[i]);
    }
}


/**
 * @brief Set big number to zero
 *
 * @param[out] r  Pointer to bn384_t to clear
 */
void
bn384_zero                     (bn384_t*                r)
{
    secure_memzero(r->d, sizeof(r->d));
}


/**
 * @brief Copy big number
 *
 * @param[out] r  Pointer to destination bn384_t
 * @param[in]  a  Pointer to source bn384_t
 */
void
bn384_copy                     (bn384_t*                r,
                                const bn384_t*          a)
{
    secure_memcpy(r->d, a->d, sizeof(r->d));
}


/**
 * @brief Compare two big numbers
 *
 * @param[in] a  Pointer to first operand
 * @param[in] b  Pointer to second operand
 * @return       -1 if a < b, 0 if a == b, 1 if a > b
 *
 * CONSTANT-TIME COMPARISON (Side-Channel Attack Prevention)
 * =========================================================
 *
 * Process ALL words regardless of where differences occur.
 * Use bitwise operations that compile to branch-free code.
 *
 * ALGORITHM (gt/lt/mask accumulator pattern):
 * - gt: tracks if a > b has been found in more significant words
 * - lt: tracks if a < b has been found in more significant words
 * - mask: prevents earlier differences from being overwritten
 */
int
bn384_cmp                      (const bn384_t*          a,
                                const bn384_t*          b)
{
    int                         i;
    bn_word                     gt;
    bn_word                     lt;
    bn_word                     mask;

    gt = 0;
    lt = 0;

    for (i = BN_WORDS - 1; i >= 0; i--)
    {
        mask = ~(gt | lt) & 1;
        gt |= ((a->d[i] > b->d[i]) & mask);
        lt |= ((a->d[i] < b->d[i]) & mask);
    }

    return (int)gt - (int)lt;
}


/*============================================================================*/
/* BigNum Arithmetic Operations                                               */
/*============================================================================*/

/**
 * @brief Big number addition
 *
 * Computes r = a + b with carry propagation.
 *
 * @param[out] r  Pointer to result (may alias a or b)
 * @param[in]  a  Pointer to first operand
 * @param[in]  b  Pointer to second operand
 * @return        Carry out (0 or 1)
 */
bn_word
bn384_add                      (bn384_t*                r,
                                const bn384_t*          a,
                                const bn384_t*          b)
{
    int                         i;
    bn_dword                    sum;
    bn_word                     carry;

    carry = 0;

    for (i = 0; i < BN_WORDS; i++)
    {
        sum = (bn_dword)a->d[i] + (bn_dword)b->d[i] + carry;
        r->d[i] = (bn_word)sum;
        carry = (bn_word)(sum >> 32);
    }

    return carry;
}


/*============================================================================*/
/* Constant-Time Helper Functions (Side-Channel Attack Prevention)            */
/*============================================================================*/

/**
 * @brief Constant-time greater-than-or-equal comparison
 *
 * Returns 1 if a >= b, 0 otherwise. This function executes in constant time
 * regardless of the input values.
 *
 * @param[in] a  First operand
 * @param[in] b  Second operand
 * @return       1 if a >= b, 0 if a < b
 */
bn_word
bn384_gte                      (const bn384_t*          a,
                                const bn384_t*          b)
{
    int                         i;
    bn_dword                    diff;
    bn_word                     borrow;

    borrow = 0;

    for (i = 0; i < BN_WORDS; i++)
    {
        diff = (bn_dword)a->d[i] - (bn_dword)b->d[i] - borrow;
        borrow = (diff >> 32) & 1;
    }

    return borrow ^ 1;
}


/**
 * @brief Constant-time conditional subtraction
 *
 * Computes r = a - b if condition is true, r = a if condition is false.
 * Executes in constant time regardless of the condition value.
 *
 * @param[out] r          Result (may alias a, but not b)
 * @param[in]  a          First operand
 * @param[in]  b          Second operand (subtracted if cond is true)
 * @param[in]  cond       Condition: 1 to subtract, 0 to copy a unchanged
 */
void
bn384_cond_sub                 (bn384_t*                r,
                                const bn384_t*          a,
                                const bn384_t*          b,
                                bn_word                 cond)
{
    int                         i;
    bn_dword                    diff;
    bn_word                     borrow;
    bn_word                     mask;
    bn_word                     sub_word;

    mask = 0 - cond;
    borrow = 0;

    for (i = 0; i < BN_WORDS; i++)
    {
        diff = (bn_dword)a->d[i] - (bn_dword)b->d[i] - borrow;
        sub_word = (bn_word)diff;
        borrow = (diff >> 32) & 1;

        r->d[i] = (sub_word & mask) | (a->d[i] & ~mask);
    }
}


/*============================================================================*/
/* Montgomery Operations                                                      */
/*============================================================================*/

/**
 * @brief Compute Montgomery constant n0 = -N^(-1) mod 2^32
 *
 * Uses Newton's method to compute the modular inverse.
 * The iteration x = x * (2 - n * x) converges quadratically.
 *
 * @param[in] n  Least significant word of the modulus (must be odd)
 * @return       -N^(-1) mod 2^32
 */
bn_word
compute_n0                     (bn_word                 n)
{
    bn_word                     x;
    int                         i;

    /* Newton iteration: x_{i+1} = x_i * (2 - n * x_i) mod 2^32
     * Starting with x_0 = 1, converges in 5 iterations for 32-bit */
    x = 1;
    for (i = 0; i < 5; i++)
    {
        x = x * (2 - n * x);
    }

    /* Return -x mod 2^32 = (0 - x) with unsigned wraparound */
    return (bn_word)(0 - x);
}


/**
 * @brief Initialize Montgomery context for a modulus
 *
 * Copies the modulus and computes the Montgomery constant n0.
 * R^2 mod N is NOT precomputed here; use compute_rr() separately.
 *
 * @param[out] ctx  Pointer to context to initialize
 * @param[in]  n    Pointer to odd modulus N (must be > 1)
 *
 * @note The modulus N must be odd (required for Montgomery reduction)
 */
void
bn_mont_init                   (bn_mont_ctx*            ctx,
                                const bn384_t*          n)
{
    /* Copy modulus N to context */
    bn384_copy(&ctx->n, n);

    /* Compute n0 = -N^(-1) mod 2^32 */
    ctx->n0 = compute_n0(n->d[0]);
}


/**
 * @brief Compute R^2 mod N where R = 2^3072
 *
 * Computes R^2 mod N by repeated doubling. Starts with rr = 1
 * and doubles 6144 times (2 * BN_BITS) while reducing mod N.
 *
 * After 3072 doublings: rr = 2^3072 mod N = R mod N
 * After 6144 doublings: rr = 2^6144 mod N = R^2 mod N
 *
 * @param[out] rr   Pointer to result buffer (R^2 mod N)
 * @param[in]  ctx  Pointer to initialized Montgomery context
 */
void
compute_rr                     (bn384_t*                rr,
                                const bn_mont_ctx*      ctx)
{
    int                         i;
    bn_word                     carry;
    bn_word                     subtract_needed;

    bn384_zero(rr);
    rr->d[0] = 1;

    for (i = 0; i < BN_BITS * 2; i++)
    {
        /* rr = rr * 2 (double) */
        carry = bn384_add(rr, rr, rr);

        /* Constant-time conditional subtraction */
        subtract_needed = carry | bn384_gte(rr, &ctx->n);
        bn384_cond_sub(rr, rr, &ctx->n, subtract_needed);
    }
}


/**
 * @brief CIOS fused Montgomery multiplication
 *
 * Computes r = a * b * R^(-1) mod N where R = 2^3072.
 * Uses the Coarsely Integrated Operand Scanning (CIOS) method
 * that fuses multiplication and reduction into a single pass.
 *
 * Stack usage: t[BN_WORDS + 2] = 392 bytes (vs 768 bytes for
 * separate multiply + reduce with double-width intermediate).
 *
 * @param[out] r    Pointer to result (may alias a and/or b)
 * @param[in]  a    Pointer to first operand in Montgomery form
 * @param[in]  b    Pointer to second operand in Montgomery form
 * @param[in]  ctx  Pointer to initialized Montgomery context
 *
 * ALGORITHM (CIOS):
 * =================
 * For each word a[i]:
 *   Step 1: Accumulate a[i] * b into t (multiply)
 *   Step 2: Compute m = t[0] * n0, add m * N, shift right 32 (reduce)
 *
 * After all iterations, t holds a * b * R^(-1) mod N (possibly + N).
 * A final conditional subtraction ensures the result is in [0, N).
 */
void
bn_mont_mul_cios               (bn384_t*                r,
                                const bn384_t*          a,
                                const bn384_t*          b,
                                const bn_mont_ctx*      ctx)
{
    bn_word                     t[BN_WORDS + 2];
    int                         i;
    int                         j;
    bn_dword                    uv;
    bn_word                     carry;
    bn_word                     m;

    /* Initialize accumulator to zero */
    for (i = 0; i < BN_WORDS + 2; i++)
    {
        t[i] = 0;
    }

    for (i = 0; i < BN_WORDS; i++)
    {
        /* Step 1: t = t + a[i] * b (multiply-accumulate) */
        carry = 0;
        for (j = 0; j < BN_WORDS; j++)
        {
            uv = (bn_dword)a->d[i] * (bn_dword)b->d[j] +
                 (bn_dword)t[j] + carry;
            t[j] = (bn_word)uv;
            carry = (bn_word)(uv >> 32);
        }
        uv = (bn_dword)t[BN_WORDS] + carry;
        t[BN_WORDS] = (bn_word)uv;
        t[BN_WORDS + 1] = (bn_word)(uv >> 32);

        /* Step 2: t = (t + m * N) >> 32 (reduce and shift)
         *
         * m = t[0] * n0 mod 2^32 ensures t[0] + m*N[0] = 0 (mod 2^32)
         * so the low word becomes zero and the right-shift is exact. */
        m = t[0] * ctx->n0;

        /* First word: low result is zero by construction, keep carry */
        uv = (bn_dword)m * (bn_dword)ctx->n.d[0] + (bn_dword)t[0];
        carry = (bn_word)(uv >> 32);

        /* Remaining words: accumulate m * N[j] + t[j] + carry, shift */
        for (j = 1; j < BN_WORDS; j++)
        {
            uv = (bn_dword)m * (bn_dword)ctx->n.d[j] +
                 (bn_dword)t[j] + carry;
            t[j - 1] = (bn_word)uv;
            carry = (bn_word)(uv >> 32);
        }

        /* Propagate carry into top words */
        uv = (bn_dword)t[BN_WORDS] + carry;
        t[BN_WORDS - 1] = (bn_word)uv;
        t[BN_WORDS] = t[BN_WORDS + 1] + (bn_word)(uv >> 32);
    }

    /* Copy result to r (t[0..BN_WORDS-1]) */
    for (i = 0; i < BN_WORDS; i++)
    {
        r->d[i] = t[i];
    }

    /* Constant-time conditional subtraction:
     * If overflow (t[BN_WORDS] != 0) or r >= N, subtract N */
    {
        bn_word                 subtract_needed;

        subtract_needed = t[BN_WORDS] | bn384_gte(r, &ctx->n);
        bn384_cond_sub(r, r, &ctx->n, subtract_needed);
    }

    /* Clear sensitive intermediate data */
    secure_memzero(t, sizeof(t));
}


/**
 * @brief Montgomery reduction only (convert from Montgomery form)
 *
 * Computes r = a * R^(-1) mod N using the shift-reduce method.
 * This is equivalent to Montgomery multiplication by 1, but uses
 * a smaller temporary buffer (BN_WORDS + 1 words = 388 bytes).
 *
 * @param[out] r    Pointer to result in normal form (may alias a)
 * @param[in]  a    Pointer to input in Montgomery form
 * @param[in]  ctx  Pointer to initialized Montgomery context
 *
 * ALGORITHM:
 * ==========
 * Copy a to t[0..n-1], set t[n] = 0.
 * For i = 0 to n-1:
 *   m = t[0] * n0
 *   t = (t + m * N) >> 32    (absorb low word, shift right)
 * Conditional subtract if t >= N.
 *
 * Each iteration divides by 2^32 while maintaining t = a * 2^(-32*i) mod N.
 * After n iterations: t = a * R^(-1) mod N.
 */
void
bn_mont_reduce_only            (bn384_t*                r,
                                const bn384_t*          a,
                                const bn_mont_ctx*      ctx)
{
    bn_word                     t[BN_WORDS + 1];
    int                         i;
    int                         j;
    bn_dword                    uv;
    bn_word                     m;
    bn_word                     carry;

    /* Copy input to temporary buffer */
    for (i = 0; i < BN_WORDS; i++)
    {
        t[i] = a->d[i];
    }
    t[BN_WORDS] = 0;

    /* Montgomery reduction: shift-reduce loop */
    for (i = 0; i < BN_WORDS; i++)
    {
        /* m = t[0] * n0 ensures (t[0] + m * N[0]) mod 2^32 = 0 */
        m = t[0] * ctx->n0;

        /* First word: result is zero by construction, keep carry */
        uv = (bn_dword)m * (bn_dword)ctx->n.d[0] + (bn_dword)t[0];
        carry = (bn_word)(uv >> 32);

        /* Remaining words: accumulate and shift */
        for (j = 1; j < BN_WORDS; j++)
        {
            uv = (bn_dword)m * (bn_dword)ctx->n.d[j] +
                 (bn_dword)t[j] + carry;
            t[j - 1] = (bn_word)uv;
            carry = (bn_word)(uv >> 32);
        }

        /* Propagate carry into top word */
        uv = (bn_dword)t[BN_WORDS] + carry;
        t[BN_WORDS - 1] = (bn_word)uv;
        t[BN_WORDS] = (bn_word)(uv >> 32);
    }

    /* Copy result */
    for (i = 0; i < BN_WORDS; i++)
    {
        r->d[i] = t[i];
    }

    /* Constant-time conditional subtraction:
     * If t[BN_WORDS] != 0 or r >= N, subtract N */
    {
        bn_word                 subtract_needed;

        subtract_needed = t[BN_WORDS] | bn384_gte(r, &ctx->n);
        bn384_cond_sub(r, r, &ctx->n, subtract_needed);
    }

    /* Clear sensitive intermediate data */
    secure_memzero(t, sizeof(t));
}


/*============================================================================*/
/* PKCS#1 Verification                                                        */
/*============================================================================*/

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
int
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

/**
 * @brief Verify RSA 3072 PKCS#1 v1.5 signature with SHA-256
 *
 * Stack-optimized implementation using two shared buffers (buf1/buf2)
 * that are reused across different phases of the computation.
 *
 * Buffer usage timeline:
 * @verbatim
 * Phase  | buf1           | buf2
 * -------|----------------|------------------
 * Init   | N (modulus)     | sig (signature)
 * MontInit| (free)         | sig
 * RR     | R^2 mod N       | sig
 * ToMont | R^2 mod N       | sig_mont
 * Backup | sig_mont (copy) | sig_mont
 * Square | sig_mont        | sig^(2^k)_mont
 * MulFin | sig_mont        | sig^65537_mont
 * FromMnt| result (normal) | (done)
 * Verify | result          | decrypted bytes
 * @endverbatim
 *
 * Worst-case stack usage: ~1660 bytes
 *   rsa3072_verify: ctx(388) + buf1(384) + buf2(384) + hash(32) + locals(~16)
 *   + bn_mont_mul_cios: t(392) + locals(~24) + call overhead(~32)
 */
int
rsa3072_verify                 (const uint8_t*          p_public_n,
                                const uint8_t*          p_message,
                                size_t                  message_len,
                                const uint8_t*          p_signature)
{
    bn_mont_ctx                 ctx;
    bn384_t                     buf1;
    bn384_t                     buf2;
    uint8_t                     hash[SHA256_HASH_SIZE];
    int                         ret;
    int                         i;

    /* Step 0: Validate input parameters */
    if ((p_public_n == NULL) || (p_message == NULL) || (p_signature == NULL))
    {
        return RSA3072_ERR_PARAM;
    }

    /* Step 1: Compute SHA-256 hash of the message */
    sha256(p_message, message_len, hash);

    /* Step 2: Convert inputs from big-endian bytes to internal format
     * buf1 = N (public modulus), buf2 = signature */
    bn384_from_bytes(&buf1, p_public_n);
    bn384_from_bytes(&buf2, p_signature);

    /* Step 3: Verify signature < N (required for valid RSA signature) */
    if (bn384_cmp(&buf2, &buf1) >= 0)
    {
        return RSA3072_ERR_VERIFY;
    }

    /* Step 4: Initialize Montgomery context (N + n0 only)
     * After this, N is stored in ctx.n and buf1 is free */
    bn_mont_init(&ctx, &buf1);

    /* Step 5: Compute R^2 mod N into buf1 (6144 modular doublings) */
    compute_rr(&buf1, &ctx);

    /* Step 6: Convert signature to Montgomery form
     * buf2 = sig * R^2 * R^(-1) mod N = sig * R mod N */
    bn_mont_mul_cios(&buf2, &buf2, &buf1, &ctx);

    /* Step 7: Save sig_mont to buf1 for the final multiply
     * buf1 = sig_mont (backup), buf2 = sig_mont (working copy) */
    bn384_copy(&buf1, &buf2);

    /* Step 8: Compute sig^(2^16) in Montgomery form (16 squarings)
     *
     * 65537 = 0x10001 = 2^16 + 1
     * a^65537 = a^(2^16) * a = square 16 times, then multiply by a */
    for (i = 0; i < 16; i++)
    {
        bn_mont_mul_cios(&buf2, &buf2, &buf2, &ctx);
    }

    /* Step 9: Final multiply by original sig_mont
     * buf2 = sig^(2^16) * sig = sig^65537 in Montgomery form */
    bn_mont_mul_cios(&buf2, &buf2, &buf1, &ctx);

    /* Step 10: Convert from Montgomery form
     * buf1 = buf2 * R^(-1) mod N = sig^65537 mod N */
    bn_mont_reduce_only(&buf1, &buf2, &ctx);

    /* Step 11: Convert result to big-endian byte array
     * Reuse buf2 memory as byte buffer (384 bytes = sizeof(bn384_t)) */
    bn384_to_bytes((uint8_t*)&buf2, &buf1);

    /* Step 12: Verify PKCS#1 v1.5 padding and compare hash */
    ret = pkcs1_v15_verify((const uint8_t*)&buf2, hash);

    /* Step 13: Clear all sensitive data from stack
     *
     * Using secure_memzero() to prevent compiler dead-store elimination.
     * ctx contains Montgomery constants, buf1/buf2 contain intermediate
     * computation results, hash contains the message digest. */
    secure_memzero(&ctx, sizeof(ctx));
    secure_memzero(&buf1, sizeof(buf1));
    secure_memzero(&buf2, sizeof(buf2));
    secure_memzero(hash, sizeof(hash));

    return ret;
}
