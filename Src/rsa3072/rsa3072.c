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

/**
 * @def BN2_WORDS
 * @brief Size of double-width result (for multiplication) in 32-bit words
 */
#define BN2_WORDS   192


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
 * @struct bn768_t
 * @brief 768-byte (6144-bit) big number for multiplication results
 *
 * Stores the double-width result of 384-byte multiplication.
 */
typedef struct {
    bn_word d[BN2_WORDS];   /**< Array of 32-bit words (little-endian order) */
} bn768_t;

/**
 * @struct bn_mont_ctx
 * @brief Montgomery multiplication context
 *
 * Precomputed values for efficient Montgomery modular multiplication.
 * Must be initialized with bn_mont_init() before use.
 */
typedef struct {
    bn384_t n;      /**< Modulus N */
    bn384_t rr;     /**< R^2 mod N (for Montgomery domain conversion) */
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
    const volatile uint8_t*    s = (const volatile uint8_t*)src;
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
static void
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
static void
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
static void
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
static void
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
static int
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
static bn_word
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


/**
 * @brief Big number subtraction
 *
 * Computes r = a - b with borrow propagation.
 *
 * @param[out] r  Pointer to result (may alias a or b)
 * @param[in]  a  Pointer to first operand
 * @param[in]  b  Pointer to second operand
 * @return        Borrow out (0 or 1)
 */
static bn_word
bn384_sub                      (bn384_t*                r,
                                const bn384_t*          a,
                                const bn384_t*          b)
{
    int                         i;
    bn_dword                    diff;
    bn_word                     borrow;

    borrow = 0;

    for (i = 0; i < BN_WORDS; i++)
    {
        diff = (bn_dword)a->d[i] - (bn_dword)b->d[i] - borrow;
        r->d[i] = (bn_word)diff;
        borrow = (diff >> 32) & 1;
    }

    return borrow;
}


/**
 * @brief Big number multiplication
 *
 * Computes r = a * b using schoolbook multiplication algorithm.
 * Result is 768 bytes (double width).
 *
 * @param[out] r  Pointer to 768-byte result
 * @param[in]  a  Pointer to first operand
 * @param[in]  b  Pointer to second operand
 *
 * @note r must not alias a or b
 */
static void
bn384_mul                      (bn768_t*                r,
                                const bn384_t*          a,
                                const bn384_t*          b)
{
    int                         i;
    int                         j;
    bn_dword                    uv;
    bn_word                     carry;

    /* Initialize result to zero */
    secure_memzero(r->d, sizeof(r->d));

    /* Schoolbook multiplication: O(n^2)
     * For each word a[i], multiply by all words of b and accumulate */
    for (i = 0; i < BN_WORDS; i++)
    {
        carry = 0;

        for (j = 0; j < BN_WORDS; j++)
        {
            /* uv = a[i] * b[j] + r[i+j] + carry */
            uv = (bn_dword)a->d[i] * (bn_dword)b->d[j] +
                 (bn_dword)r->d[i + j] + carry;
            r->d[i + j] = (bn_word)uv;
            carry = (bn_word)(uv >> 32);
        }

        r->d[i + BN_WORDS] = carry;
    }
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
static bn_word
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
static void
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
static bn_word
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
 * @brief Montgomery reduction
 *
 * Computes r = t * R^(-1) mod N where R = 2^3072.
 * Uses the CIOS (Coarsely Integrated Operand Scanning) method.
 *
 * @param[out]    r    Pointer to 384-byte result
 * @param[in,out] t    Pointer to 768-byte input (modified during computation)
 * @param[in]     ctx  Pointer to Montgomery context
 */
static void
bn_mont_reduce                 (bn384_t*                r,
                                bn768_t*                t,
                                const bn_mont_ctx*      ctx)
{
    int                         i;
    int                         j;
    bn_dword                    uv;
    bn_word                     m;
    bn_word                     carry;
    bn_word                     overflow;

    overflow = 0;

    /* Montgomery reduction loop:
     * For i = 0 to n-1:
     *   m = t[i] * n0 mod 2^32
     *   t = t + m * N * 2^(32*i)
     * Result is in upper half of t */
    for (i = 0; i < BN_WORDS; i++)
    {
        /* Compute quotient digit: m = t[i] * n0 mod 2^32 */
        m = t->d[i] * ctx->n0;

        /* Add m * N shifted by i words: t = t + m * N * 2^(32*i) */
        carry = 0;
        for (j = 0; j < BN_WORDS; j++)
        {
            uv = (bn_dword)m * (bn_dword)ctx->n.d[j] +
                 (bn_dword)t->d[i + j] + carry;
            t->d[i + j] = (bn_word)uv;
            carry = (bn_word)(uv >> 32);
        }

        /* Propagate carry through remaining words */
        for (j = i + BN_WORDS; j < BN2_WORDS && carry; j++)
        {
            uv = (bn_dword)t->d[j] + carry;
            t->d[j] = (bn_word)uv;
            carry = (bn_word)(uv >> 32);
        }

        /* Track overflow into word 192 (which we cannot store) */
        overflow |= carry;
    }

    /* Copy upper half of t to result: r = t[n..2n-1] */
    for (i = 0; i < BN_WORDS; i++)
    {
        r->d[i] = t->d[i + BN_WORDS];
    }

    /* Constant-time conditional subtraction:
     * If r >= N, subtract N without branching */
    {
        bn_word                 subtract_needed;

        subtract_needed = overflow | bn384_gte(r, &ctx->n);
        bn384_cond_sub(r, r, &ctx->n, subtract_needed);
    }
}


/**
 * @brief Initialize Montgomery context for a modulus
 *
 * Precomputes Montgomery constants for efficient modular multiplication.
 * This function is called once per modulus.
 *
 * @param[out] ctx  Pointer to context to initialize
 * @param[in]  n    Pointer to odd modulus N (must be > 1)
 *
 * @note The modulus N must be odd (required for Montgomery reduction)
 * @note This operation is relatively expensive (~6144 modular doublings)
 */
static void
bn_mont_init                   (bn_mont_ctx*            ctx,
                                const bn384_t*          n)
{
    int                         i;
    bn_word                     carry;

    /* Copy modulus N to context */
    bn384_copy(&ctx->n, n);

    /* Compute n0 = -N^(-1) mod 2^32 */
    ctx->n0 = compute_n0(n->d[0]);

    /*
     * Compute R^2 mod N where R = 2^3072
     *
     * Method: Start with rr = 1, then double it 2*3072 = 6144 times
     * while reducing mod N each time.
     *
     * After 3072 doublings: rr = 2^3072 mod N = R mod N
     * After 6144 doublings: rr = 2^6144 mod N = R^2 mod N
     */
    bn384_zero(&ctx->rr);
    ctx->rr.d[0] = 1;

    for (i = 0; i < BN_BITS * 2; i++)
    {
        bn_word                 subtract_needed;

        /* rr = rr * 2 (double) */
        carry = bn384_add(&ctx->rr, &ctx->rr, &ctx->rr);

        /* Constant-time conditional subtraction */
        subtract_needed = carry | bn384_gte(&ctx->rr, &ctx->n);
        bn384_cond_sub(&ctx->rr, &ctx->rr, &ctx->n, subtract_needed);
    }
}


/**
 * @brief Montgomery multiplication
 *
 * Computes r = a * b * R^(-1) mod N where R = 2^3072.
 * Both inputs must be in Montgomery form (pre-multiplied by R mod N).
 *
 * @param[out] r    Pointer to result in Montgomery form
 * @param[in]  a    Pointer to first operand in Montgomery form
 * @param[in]  b    Pointer to second operand in Montgomery form
 * @param[in]  ctx  Pointer to initialized Montgomery context
 */
static void
bn_mont_mul                    (bn384_t*                r,
                                const bn384_t*          a,
                                const bn384_t*          b,
                                const bn_mont_ctx*      ctx)
{
    bn768_t                     t;

    /* t = a * b (768-byte result) */
    bn384_mul(&t, a, b);

    /* r = t * R^(-1) mod N (Montgomery reduction) */
    bn_mont_reduce(r, &t, ctx);
}


/**
 * @brief Montgomery squaring
 *
 * Computes r = a^2 * R^(-1) mod N.
 * Equivalent to bn_mont_mul(r, a, a, ctx) but potentially optimizable.
 *
 * @param[out] r    Pointer to result in Montgomery form
 * @param[in]  a    Pointer to operand in Montgomery form
 * @param[in]  ctx  Pointer to initialized Montgomery context
 */
static void
bn_mont_sqr                    (bn384_t*                r,
                                const bn384_t*          a,
                                const bn_mont_ctx*      ctx)
{
    /* For simplicity, squaring uses general multiplication
     * (Could be optimized to ~1.5x faster with dedicated squaring) */
    bn_mont_mul(r, a, a, ctx);
}


/**
 * @brief Convert to Montgomery form
 *
 * Computes r = a * R mod N (converts normal integer to Montgomery form).
 *
 * @param[out] r    Pointer to result in Montgomery form
 * @param[in]  a    Pointer to input in normal form
 * @param[in]  ctx  Pointer to initialized Montgomery context
 */
static void
bn_to_mont                     (bn384_t*                r,
                                const bn384_t*          a,
                                const bn_mont_ctx*      ctx)
{
    /* Convert to Montgomery form: r = a * R mod N
     * Use the identity: a * R mod N = a * R^2 * R^(-1) mod N
     * So: r = Montgomery_Mul(a, R^2) */
    bn_mont_mul(r, a, &ctx->rr, ctx);
}


/**
 * @brief Convert from Montgomery form
 *
 * Computes r = a * R^(-1) mod N (converts Montgomery form to normal integer).
 *
 * @param[out] r    Pointer to result in normal form
 * @param[in]  a    Pointer to input in Montgomery form
 * @param[in]  ctx  Pointer to initialized Montgomery context
 */
static void
bn_from_mont                   (bn384_t*                r,
                                const bn384_t*          a,
                                const bn_mont_ctx*      ctx)
{
    bn768_t                     t;
    int                         i;

    /* Convert from Montgomery form: r = a * R^(-1) mod N
     * Treat a as a 768-byte number (padded with zeros) and reduce */

    /* t = a padded to 768 bytes */
    for (i = 0; i < BN_WORDS; i++)
    {
        t.d[i] = a->d[i];
    }
    for (i = BN_WORDS; i < BN2_WORDS; i++)
    {
        t.d[i] = 0;
    }

    /* r = t * R^(-1) mod N */
    bn_mont_reduce(r, &t, ctx);
}


/**
 * @brief Modular exponentiation with fixed exponent E = 65537
 *
 * Computes r = a^65537 mod N using Montgomery multiplication.
 * Optimized for the common RSA public exponent 65537 (0x10001 = 2^16 + 1).
 *
 * Algorithm uses only 16 squarings + 1 multiplication:
 * - 65537 = 2^16 + 1
 * - a^65537 = a^(2^16) * a = square 16 times, then multiply by a
 *
 * @param[out] r    Pointer to result (a^65537 mod N)
 * @param[in]  a    Pointer to base (must satisfy 0 <= a < N)
 * @param[in]  ctx  Pointer to initialized Montgomery context
 *
 * @note Input a must be less than modulus N
 * @note Result r may alias input a
 */
static void
bn_modexp_e65537               (bn384_t*                r,
                                const bn384_t*          a,
                                const bn_mont_ctx*      ctx)
{
    bn384_t                     x;
    bn384_t                     a_mont;  /* for backup */
    int                         i;

    /* Convert base a to Montgomery form: a_mont = a * R mod N */
    bn_to_mont(&a_mont, a, ctx);

    /* Copy a's Montgomery form to x */
    bn384_copy(&x, &a_mont);

    /* Compute a^65537 mod N using square-and-multiply
     *
     * 65537 = 0x10001 = 2^16 + 1 (binary: 1_0000_0000_0000_0001)
     *
     * Algorithm:
     *   x = a
     *   for i = 0 to 15:
     *       x = x^2 mod N       // 16 squarings
     *   x = x * a mod N         // 1 multiplication
     */

    /* Perform 16 squarings: x = a^(2^16) in Montgomery form */
    for (i = 0; i < 16; i++)
    {
        bn_mont_sqr(&x, &x, ctx);
    }

    /* Final multiplication by original a (in Montgomery form) */
    bn_mont_mul(&x, &x, &a_mont, ctx);

    /* Convert result back from Montgomery form: r = x * R^(-1) mod N */
    bn_from_mont(r, &x, ctx);
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
