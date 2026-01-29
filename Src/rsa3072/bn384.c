/**
 * @file bn384.c
 * @brief Minimal BigNum Implementation for RSA 3072
 *
 * 384-byte (3072-bit) integer operations optimized for RSA signature verification.
 * Uses Montgomery multiplication for efficient modular arithmetic.
 *
 * @note This implementation prioritizes code size over speed.
 * @note Uses schoolbook multiplication (O(n^2)) instead of Karatsuba.
 */

#include "bn384.h"
#include <string.h>


/*============================================================================*/
/* Basic Operations                                                           */
/*============================================================================*/

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


void
bn384_zero                     (bn384_t*                r)
{
    memset(r->d, 0, sizeof(r->d));
}


void
bn384_copy                     (bn384_t*                r,
                                const bn384_t*          a)
{
    memcpy(r->d, a->d, sizeof(r->d));
}


int
bn384_cmp                      (const bn384_t*          a,
                                const bn384_t*          b)
{
    int                         i;
    bn_word                     gt;
    bn_word                     lt;
    bn_word                     mask;

    /*
     * CONSTANT-TIME COMPARISON (Side-Channel Attack Prevention)
     * =========================================================
     *
     * WHY THIS IMPLEMENTATION:
     * The original early-return implementation leaks timing information.
     * An attacker can measure execution time to determine WHERE the first
     * difference occurs between 'a' and 'b'. In RSA verification, this
     * could help an attacker learn about the modulus or intermediate values.
     *
     * ATTACK SCENARIO:
     * If comparing signature S with modulus N:
     * - Fast return (S[95] != N[95]) -> attacker knows MSW differs
     * - Slow return (differs at S[0]) -> attacker knows 95 words match
     * This timing variation enables Bleichenbacher-style attacks.
     *
     * SOLUTION:
     * Process ALL words regardless of where differences occur.
     * Use bitwise operations that compile to branch-free code.
     *
     * ALGORITHM (gt/lt/mask accumulator pattern):
     * - gt: tracks if a > b has been found in more significant words
     * - lt: tracks if a < b has been found in more significant words
     * - mask: prevents earlier differences from being overwritten
     *
     * For each word (from MSW to LSW):
     *   If (a[i] > b[i]) and we haven't found a difference yet -> set gt=1
     *   If (a[i] < b[i]) and we haven't found a difference yet -> set lt=1
     *   Once gt or lt is set, mask prevents further changes
     *
     * This is equivalent to "find first difference" but without branches.
     */

    gt = 0;     /* Set to 1 if a > b found (and no prior difference) */
    lt = 0;     /* Set to 1 if a < b found (and no prior difference) */

    for (i = BN_WORDS - 1; i >= 0; i--)
    {
        /*
         * mask = 1 if NO difference found yet, 0 if difference already found.
         *
         * Logic: mask = ~(gt | lt) & 1
         * - If gt=0 and lt=0: mask = ~0 & 1 = 1 (keep looking)
         * - If gt=1 or lt=1:  mask = ~1 & 1 = 0 (stop updating)
         *
         * The "& 1" ensures mask is exactly 0 or 1, not 0xFFFFFFFF.
         */
        mask = ~(gt | lt) & 1;

        /*
         * Update gt: set to 1 if a[i] > b[i] AND mask is 1
         *
         * (a->d[i] > b->d[i]) returns 1 or 0 (comparison result)
         * Multiply by mask: if mask=0, result is 0 (no change)
         * OR with existing gt: preserves previous gt=1 if already set
         *
         * This is branch-free: same operations execute regardless of values.
         */
        gt |= ((a->d[i] > b->d[i]) & mask);

        /*
         * Update lt: set to 1 if a[i] < b[i] AND mask is 1
         *
         * Same logic as gt, but for less-than comparison.
         */
        lt |= ((a->d[i] < b->d[i]) & mask);
    }

    /*
     * Final result:
     * - gt=1, lt=0 -> return 1  (a > b)
     * - gt=0, lt=1 -> return -1 (a < b)
     * - gt=0, lt=0 -> return 0  (a == b)
     *
     * Formula: (int)gt - (int)lt
     * - 1 - 0 =  1
     * - 0 - 1 = -1
     * - 0 - 0 =  0
     */
    return (int)gt - (int)lt;
}


/*============================================================================*/
/* Arithmetic Operations                                                      */
/*============================================================================*/

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


bn_word
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


void
bn384_mul                      (bn768_t*                r,
                                const bn384_t*          a,
                                const bn384_t*          b)
{
    int                         i;
    int                         j;
    bn_dword                    uv;
    bn_word                     carry;

    /* Initialize result to zero */
    memset(r->d, 0, sizeof(r->d));

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
 *
 * WHY THIS IMPLEMENTATION:
 * In cryptographic code, we often need to check if a >= N (modulus) to decide
 * whether to subtract N. A simple comparison with early-return leaks timing
 * information about where the numbers differ.
 *
 * ALGORITHM:
 * - Perform subtraction a - b and check for borrow
 * - If no borrow, a >= b (return 1)
 * - If borrow occurred, a < b (return 0)
 *
 * This always performs the full subtraction, regardless of values.
 */
static bn_word
bn384_gte                      (const bn384_t*          a,
                                const bn384_t*          b)
{
    int                         i;
    bn_dword                    diff;
    bn_word                     borrow;

    /*
     * Compute a - b and track borrow propagation.
     *
     * We don't need the result, only whether borrow occurred.
     * If final borrow = 0: a >= b (subtraction succeeded)
     * If final borrow = 1: a < b (would underflow)
     */
    borrow = 0;

    for (i = 0; i < BN_WORDS; i++)
    {
        /*
         * diff = a[i] - b[i] - borrow
         *
         * Using 64-bit arithmetic:
         * - If result is negative, upper 32 bits will have bit 32 set
         * - Extract bit 32 to get new borrow
         */
        diff = (bn_dword)a->d[i] - (bn_dword)b->d[i] - borrow;
        borrow = (diff >> 32) & 1;
    }

    /*
     * Return inverse of borrow:
     * - borrow = 0 means a >= b, return 1
     * - borrow = 1 means a < b, return 0
     *
     * Formula: 1 - borrow (or equivalently: borrow ^ 1)
     */
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
 *
 * WHY THIS IMPLEMENTATION:
 * After Montgomery reduction, we need to conditionally subtract N if result >= N.
 * A simple "if (result >= N) result -= N;" branch leaks timing information:
 * - Attacker can measure if the subtraction path was taken
 * - This reveals information about intermediate values
 *
 * SOLUTION:
 * Always perform the subtraction, but use a bitmask to select the result.
 * - If cond=1: mask = 0xFFFFFFFF, use subtracted value
 * - If cond=0: mask = 0x00000000, use original value
 *
 * ALGORITHM:
 * For each word i:
 *   sub_result[i] = a[i] - b[i] - borrow   (always computed)
 *   r[i] = (sub_result[i] & mask) | (a[i] & ~mask)
 *
 * The mask selects which value to output without any branches.
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

    /*
     * Create selection mask from condition.
     *
     * cond is 0 or 1. We need:
     * - cond=1 -> mask = 0xFFFFFFFF (all bits set)
     * - cond=0 -> mask = 0x00000000 (all bits clear)
     *
     * Method: 0 - cond (using unsigned wraparound)
     * - 0 - 1 = 0xFFFFFFFF (two's complement)
     * - 0 - 0 = 0x00000000
     *
     * Alternative: (bn_word)(-(int32_t)cond)
     * But 0 - cond works correctly for unsigned types.
     */
    mask = 0 - cond;

    borrow = 0;

    for (i = 0; i < BN_WORDS; i++)
    {
        /*
         * Always compute the subtraction result.
         * This ensures constant execution time regardless of condition.
         */
        diff = (bn_dword)a->d[i] - (bn_dword)b->d[i] - borrow;
        sub_word = (bn_word)diff;
        borrow = (diff >> 32) & 1;

        /*
         * Select output based on mask:
         *
         * r[i] = (sub_word & mask) | (a->d[i] & ~mask)
         *
         * If mask = 0xFFFFFFFF (cond=1):
         *   r[i] = (sub_word & 0xFFFFFFFF) | (a->d[i] & 0x00000000)
         *        = sub_word | 0
         *        = sub_word  (use subtracted value)
         *
         * If mask = 0x00000000 (cond=0):
         *   r[i] = (sub_word & 0x00000000) | (a->d[i] & 0xFFFFFFFF)
         *        = 0 | a->d[i]
         *        = a->d[i]   (keep original value)
         *
         * No branches, same operations execute in both cases.
         */
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

    /*
     * CONSTANT-TIME CONDITIONAL SUBTRACTION (Side-Channel Attack Prevention)
     * =======================================================================
     *
     * WHY THIS IMPLEMENTATION:
     * The original code used: if (overflow || bn384_cmp(r, &ctx->n) >= 0) { bn384_sub(...); }
     * This branch leaks timing information:
     * - If branch is taken: one execution path (longer)
     * - If branch is skipped: another execution path (shorter)
     * Attacker can measure this to learn about the intermediate value.
     *
     * SECURITY IMPLICATION:
     * In Montgomery reduction, whether we subtract N depends on the result value.
     * Leaking this information helps attackers perform timing-based attacks
     * to recover private information about the computation.
     *
     * SOLUTION:
     * Use bn384_cond_sub() which ALWAYS performs the same operations,
     * but uses bitmask selection to choose the output.
     *
     * CONDITION LOGIC:
     * subtract_needed = overflow | (r >= N)
     *
     * Using bn384_gte() for constant-time comparison:
     * - bn384_gte(r, &ctx->n) returns 1 if r >= N, 0 otherwise
     * - OR with overflow to handle the 2^3072 overflow case
     */
    {
        bn_word                 subtract_needed;

        /*
         * Compute condition: should we subtract N?
         *
         * subtract_needed = overflow | bn384_gte(r, &ctx->n)
         *
         * Both overflow and bn384_gte() return 0 or 1.
         * OR combines them: subtract if either condition is true.
         */
        subtract_needed = overflow | bn384_gte(r, &ctx->n);

        /*
         * Perform constant-time conditional subtraction.
         *
         * If subtract_needed = 1: r = r - N
         * If subtract_needed = 0: r = r (unchanged)
         *
         * bn384_cond_sub() executes identical operations regardless of
         * subtract_needed value, preventing timing leakage.
         */
        bn384_cond_sub(r, r, &ctx->n, subtract_needed);
    }
}


void
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
     * rr = 1
     * for i = 0 to 6143:
     *     rr = 2 * rr mod N
     *
     * After 3072 doublings: rr = 2^3072 mod N = R mod N
     * After 6144 doublings: rr = 2^6144 mod N = R^2 mod N
     *
     * SECURITY NOTE:
     * Although bn_mont_init() is called once per key (not per signature),
     * we still use constant-time operations for defense-in-depth.
     * This prevents timing attacks even in scenarios where:
     * - Multiple keys are compared
     * - Init timing is measurable
     * - Future code changes expose this path
     */
    bn384_zero(&ctx->rr);
    ctx->rr.d[0] = 1;

    for (i = 0; i < BN_BITS * 2; i++)
    {
        bn_word                 subtract_needed;

        /* rr = rr * 2 (double) */
        carry = bn384_add(&ctx->rr, &ctx->rr, &ctx->rr);

        /*
         * CONSTANT-TIME CONDITIONAL SUBTRACTION
         *
         * Original code: if (carry || bn384_cmp(&ctx->rr, &ctx->n) >= 0)
         *
         * WHY CONSTANT-TIME HERE:
         * Even though this runs during initialization (not per-message),
         * the timing of this loop could leak information about the modulus N.
         * An attacker measuring init time could learn:
         * - How often rr >= N occurred (depends on N's bit pattern)
         * - Statistical properties of N
         *
         * For cryptographic robustness, we apply constant-time principles
         * throughout the entire BigNum library.
         */
        subtract_needed = carry | bn384_gte(&ctx->rr, &ctx->n);
        bn384_cond_sub(&ctx->rr, &ctx->rr, &ctx->n, subtract_needed);
    }
}


void
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


void
bn_mont_sqr                    (bn384_t*                r,
                                const bn384_t*          a,
                                const bn_mont_ctx*      ctx)
{
    /* For simplicity, squaring uses general multiplication
     * (Could be optimized to ~1.5x faster with dedicated squaring) */
    bn_mont_mul(r, a, a, ctx);
}


void
bn_to_mont                     (bn384_t*                r,
                                const bn384_t*          a,
                                const bn_mont_ctx*      ctx)
{
    /* Convert to Montgomery form: r = a * R mod N
     * Use the identity: a * R mod N = a * R^2 * R^(-1) mod N
     * So: r = Montgomery_Mul(a, R^2) */
    bn_mont_mul(r, a, &ctx->rr, ctx);
}


void
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


/*============================================================================*/
/* RSA Operation                                                              */
/*============================================================================*/

void
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
     * a^65537 = a^(2^16 + 1)
     *         = a^(2^16) * a^1
     *         = (((a^2)^2)^2 ... 16 times) * a
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
