/**
 * @file bn384.h
 * @brief Minimal BigNum Implementation for RSA 3072
 *
 * 384-byte (3072-bit) integer operations optimized for RSA signature verification.
 * Uses Montgomery multiplication for efficient modular arithmetic.
 *
 * @note Code size: ~1.5 KB (ARM Thumb-2, -Os)
 * @note Uses little-endian word order internally (word[0] = LSW)
 * @note External byte arrays are big-endian (network byte order)
 */

#ifndef BN384_H
#define BN384_H

#include <stdint.h>
#include <stddef.h>


/*============================================================================*/
/* Constants                                                                  */
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
/* Types                                                                      */
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
/* Basic Operations                                                           */
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
void bn384_from_bytes(bn384_t* r, const uint8_t* bytes);

/**
 * @brief Convert bn384_t to big-endian byte array
 *
 * Converts internal little-endian word representation to a 384-byte
 * big-endian byte array.
 *
 * @param[out] bytes  Pointer to 384-byte output buffer
 * @param[in]  a      Pointer to source bn384_t
 */
void bn384_to_bytes(uint8_t* bytes, const bn384_t* a);

/**
 * @brief Set big number to zero
 *
 * @param[out] r  Pointer to bn384_t to clear
 */
void bn384_zero(bn384_t* r);

/**
 * @brief Copy big number
 *
 * @param[out] r  Pointer to destination bn384_t
 * @param[in]  a  Pointer to source bn384_t
 */
void bn384_copy(bn384_t* r, const bn384_t* a);

/**
 * @brief Compare two big numbers
 *
 * @param[in] a  Pointer to first operand
 * @param[in] b  Pointer to second operand
 * @return       -1 if a < b, 0 if a == b, 1 if a > b
 */
int bn384_cmp(const bn384_t* a, const bn384_t* b);


/*============================================================================*/
/* Arithmetic Operations                                                      */
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
bn_word bn384_add(bn384_t* r, const bn384_t* a, const bn384_t* b);

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
bn_word bn384_sub(bn384_t* r, const bn384_t* a, const bn384_t* b);

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
void bn384_mul(bn768_t* r, const bn384_t* a, const bn384_t* b);


/*============================================================================*/
/* Montgomery Operations                                                      */
/*============================================================================*/

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
void bn_mont_init(bn_mont_ctx* ctx, const bn384_t* n);

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
void bn_mont_mul(bn384_t* r, const bn384_t* a, const bn384_t* b, const bn_mont_ctx* ctx);

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
void bn_mont_sqr(bn384_t* r, const bn384_t* a, const bn_mont_ctx* ctx);

/**
 * @brief Convert to Montgomery form
 *
 * Computes r = a * R mod N (converts normal integer to Montgomery form).
 *
 * @param[out] r    Pointer to result in Montgomery form
 * @param[in]  a    Pointer to input in normal form
 * @param[in]  ctx  Pointer to initialized Montgomery context
 */
void bn_to_mont(bn384_t* r, const bn384_t* a, const bn_mont_ctx* ctx);

/**
 * @brief Convert from Montgomery form
 *
 * Computes r = a * R^(-1) mod N (converts Montgomery form to normal integer).
 *
 * @param[out] r    Pointer to result in normal form
 * @param[in]  a    Pointer to input in Montgomery form
 * @param[in]  ctx  Pointer to initialized Montgomery context
 */
void bn_from_mont(bn384_t* r, const bn384_t* a, const bn_mont_ctx* ctx);


/*============================================================================*/
/* RSA Operation                                                              */
/*============================================================================*/

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
void bn_modexp_e65537(bn384_t* r, const bn384_t* a, const bn_mont_ctx* ctx);

#endif /* BN384_H */
