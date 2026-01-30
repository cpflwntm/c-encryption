/**
 * @file sha256.c
 * @brief Minimal SHA-256 Implementation
 *
 * Size-optimized SHA-256 hash algorithm implementation for embedded systems.
 * Based on FIPS 180-4 (Secure Hash Standard).
 *
 * @note This implementation prioritizes code size over speed.
 * @note No loop unrolling or architecture-specific optimizations.
 */

#include "sha256.h"


/*============================================================================*/
/* Constants                                                                  */
/*============================================================================*/

/**
 * @brief SHA-256 round constants K[0..63]
 *
 * First 32 bits of the fractional parts of the cube roots
 * of the first 64 prime numbers (2..311).
 */
static const uint32_t K[64] = {
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};

/**
 * @brief SHA-256 initial hash values H0[0..7]
 *
 * First 32 bits of the fractional parts of the square roots
 * of the first 8 prime numbers (2, 3, 5, 7, 11, 13, 17, 19).
 */
static const uint32_t H0[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};


/*============================================================================*/
/* Macros                                                                     */
/*============================================================================*/

/**
 * @def ROTR(x, n)
 * @brief Rotate right (circular right shift) by n bits
 * @param x Value to rotate
 * @param n Number of bits to rotate (0-31)
 */
#define ROTR(x, n)  (((x) >> (n)) | ((x) << (32 - (n))))

/**
 * @def CH(x, y, z)
 * @brief SHA-256 Ch function: (x AND y) XOR (NOT x AND z)
 */
#define CH(x, y, z)   (((x) & (y)) ^ (~(x) & (z)))

/**
 * @def MAJ(x, y, z)
 * @brief SHA-256 Maj function: (x AND y) XOR (x AND z) XOR (y AND z)
 */
#define MAJ(x, y, z)  (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

/**
 * @def EP0(x)
 * @brief SHA-256 Sigma0 function: ROTR(x,2) XOR ROTR(x,13) XOR ROTR(x,22)
 */
#define EP0(x)        (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))

/**
 * @def EP1(x)
 * @brief SHA-256 Sigma1 function: ROTR(x,6) XOR ROTR(x,11) XOR ROTR(x,25)
 */
#define EP1(x)        (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))

/**
 * @def SIG0(x)
 * @brief SHA-256 sigma0 function: ROTR(x,7) XOR ROTR(x,18) XOR SHR(x,3)
 */
#define SIG0(x)       (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))

/**
 * @def SIG1(x)
 * @brief SHA-256 sigma1 function: ROTR(x,17) XOR ROTR(x,19) XOR SHR(x,10)
 */
#define SIG1(x)       (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))


/*============================================================================*/
/* Internal Functions                                                         */
/*============================================================================*/

/**
 * @brief Secure memory clearing (prevents compiler optimization)
 *
 * Clears sensitive data from memory using a volatile pointer to prevent
 * the compiler from optimizing away the memory clearing operation.
 *
 * @param[out] ptr  Pointer to memory to clear
 * @param[in]  len  Number of bytes to clear
 *
 * WHY THIS IS NECESSARY IN SHA-256:
 * =================================
 *
 * The SHA-256 context (sha256_ctx) contains:
 * - state[8]: Intermediate hash state (256 bits)
 * - count[2]: Message length counter
 * - buffer[64]: Partial message block
 *
 * After sha256_final() outputs the hash, these values are no longer needed.
 * However, they contain:
 * - Information about the message being hashed
 * - Intermediate computation states
 *
 * ATTACK SCENARIOS:
 * 1. Length extension attacks: If attacker knows state[] after hashing,
 *    they can compute hash(message || padding || extension) without
 *    knowing the original message.
 *
 * 2. Partial information leakage: buffer[] may contain the last partial
 *    block of the message, revealing plaintext content.
 *
 * 3. Cross-function attacks: A later buffer overflow could read the
 *    stack area where this context was stored.
 *
 * COMPILER OPTIMIZATION PROBLEM:
 * Standard memset() at the end of sha256_final():
 *     memset(ctx, 0, sizeof(*ctx));
 *     // function returns, ctx is never read again
 *
 * The compiler sees this as a "dead store" because:
 * - ctx is about to go out of scope (or is done being used)
 * - No code reads ctx after the memset
 * - Therefore, the memset "has no observable effect"
 *
 * With -O2 or -O3, GCC/Clang may remove this memset entirely.
 *
 * SOLUTION:
 * volatile uint8_t* prevents the compiler from making assumptions
 * about whether the memory will be read. Each byte write is forced
 * to actually occur in the generated assembly.
 */
static void
secure_memzero                 (void*                   ptr,
                                size_t                  len)
{
    volatile uint8_t*           p = (volatile uint8_t*)ptr;
    size_t                      i;

    /*
     * Write each byte individually through volatile pointer.
     *
     * The 'volatile' qualifier guarantees:
     * - Every write to p[i] generates a real store instruction
     * - The compiler cannot reorder, merge, or eliminate these stores
     * - This works even at maximum optimization levels
     */
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
 * @brief Load 32-bit value from big-endian byte array
 *
 * @param[in] p  Pointer to 4-byte big-endian array
 * @return       32-bit value in host byte order
 */
static uint32_t
load_be32                      (const uint8_t*          p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |
           ((uint32_t)p[3]);
}

/**
 * @brief Store 32-bit value to big-endian byte array
 *
 * @param[out] p  Pointer to 4-byte output buffer
 * @param[in]  x  32-bit value to store
 */
static void
store_be32                     (uint8_t*                p,
                                uint32_t                x)
{
    p[0] = (uint8_t)(x >> 24);
    p[1] = (uint8_t)(x >> 16);
    p[2] = (uint8_t)(x >> 8);
    p[3] = (uint8_t)(x);
}

/**
 * @brief Process one 64-byte (512-bit) message block
 *
 * Performs the SHA-256 compression function on a single block.
 * Updates the hash state with the result.
 *
 * @param[in,out] state  Current hash state (8 x 32-bit words)
 * @param[in]     block  64-byte input block to process
 */
static void
sha256_transform               (uint32_t                state[8],
                                const uint8_t           block[64])
{
    uint32_t                    W[64];
    uint32_t                    a, b, c, d, e, f, g, h;
    uint32_t                    t1, t2;
    int                         i;

    /* Prepare message schedule W[0..63] */
    for (i = 0; i < 16; i++)
    {
        W[i] = load_be32(&block[i * 4]);
    }
    for (i = 16; i < 64; i++)
    {
        W[i] = SIG1(W[i - 2]) + W[i - 7] + SIG0(W[i - 15]) + W[i - 16];
    }

    /* Initialize working variables with current hash value */
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    /* Main compression loop (64 rounds) */
    for (i = 0; i < 64; i++)
    {
        t1 = h + EP1(e) + CH(e, f, g) + K[i] + W[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    /* Add compressed chunk to current hash value */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}


/*============================================================================*/
/* Public API                                                                 */
/*============================================================================*/

void
sha256_init                    (sha256_ctx*             ctx)
{
    secure_memcpy(ctx->state, H0, sizeof(H0));
    ctx->count[0] = 0;
    ctx->count[1] = 0;
}


void
sha256_update                  (sha256_ctx*             ctx,
                                const uint8_t*          data,
                                size_t                  len)
{
    size_t                      i;
    size_t                      idx;

    /* Compute current buffer index from bit count */
    idx = (ctx->count[0] >> 3) & 0x3F;

    /* Update 64-bit bit count (count[0] = low, count[1] = high) */
    ctx->count[0] += (uint32_t)(len << 3);
    if (ctx->count[0] < (uint32_t)(len << 3))
    {
        ctx->count[1]++;  /* Handle overflow */
    }
    ctx->count[1] += (uint32_t)(len >> 29);

    /* Process input data byte by byte */
    for (i = 0; i < len; i++)
    {
        ctx->buffer[idx++] = data[i];
        if (idx == 64)
        {
            sha256_transform(ctx->state, ctx->buffer);
            idx = 0;
        }
    }
}


void
sha256_final                   (sha256_ctx*             ctx,
                                uint8_t                 hash[SHA256_HASH_SIZE])
{
    uint8_t                     pad[64];
    uint8_t                     len_bits[8];
    size_t                      idx;
    size_t                      pad_len;
    int                         i;

    /* Store original message length in bits (big-endian) */
    store_be32(&len_bits[0], ctx->count[1]);
    store_be32(&len_bits[4], ctx->count[0]);

    /* Calculate padding length:
     * Pad to 56 bytes mod 64 (leaving 8 bytes for length) */
    idx = (ctx->count[0] >> 3) & 0x3F;
    pad_len = (idx < 56) ? (56 - idx) : (120 - idx);

    /* Apply padding: 0x80 followed by zeros */
    secure_memzero(pad, sizeof(pad));
    pad[0] = 0x80;
    sha256_update(ctx, pad, pad_len);

    /* Append 64-bit message length */
    sha256_update(ctx, len_bits, 8);

    /* Output final hash value (big-endian) */
    for (i = 0; i < 8; i++)
    {
        store_be32(&hash[i * 4], ctx->state[i]);
    }

    /*
     * SECURITY-CRITICAL: Clear context to prevent hash state leakage
     *
     * Using secure_memzero() instead of memset() because:
     *
     * 1. COMPILER OPTIMIZATION RISK:
     *    After this function returns, ctx is never read again.
     *    A standard memset() is a "dead store" that compilers
     *    (especially with -O2 or -O3) may legally eliminate.
     *
     * 2. DATA BEING PROTECTED:
     *    - ctx->state[]: Final hash state before output conversion
     *    - ctx->buffer[]: Last partial block of input message
     *    - ctx->count[]: Total message length
     *
     * 3. ATTACK PREVENTION:
     *    - Prevents recovery of intermediate hash states
     *    - Prevents length extension attack preparation
     *    - Prevents leakage of partial message content
     *
     * secure_memzero() uses a volatile pointer to force the compiler
     * to emit actual memory clearing instructions.
     */
    secure_memzero(ctx, sizeof(*ctx));
}


void
sha256                         (const uint8_t*          data,
                                size_t                  len,
                                uint8_t                 hash[SHA256_HASH_SIZE])
{
    sha256_ctx                  ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, hash);
}
