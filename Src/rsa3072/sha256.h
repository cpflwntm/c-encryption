/**
 * @file sha256.h
 * @brief Minimal SHA-256 Implementation
 *
 * Size-optimized SHA-256 hash algorithm implementation for embedded systems.
 * Compliant with FIPS 180-4 specification.
 *
 * @note Code size: ~1.3 KB (ARM Thumb-2, -Os)
 * @note No external dependencies except standard C library
 */

#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

/**
 * @def SHA256_BLOCK_SIZE
 * @brief SHA-256 input block size in bytes (512 bits)
 */
#define SHA256_BLOCK_SIZE   64

/**
 * @def SHA256_HASH_SIZE
 * @brief SHA-256 output hash size in bytes (256 bits)
 */
#define SHA256_HASH_SIZE    32

/**
 * @struct sha256_ctx
 * @brief SHA-256 context structure
 *
 * Holds the intermediate state during hash computation.
 * Must be initialized with sha256_init() before use.
 */
typedef struct {
    uint32_t state[8];              /**< Hash state variables (A-H) */
    uint32_t count[2];              /**< Bit count (low, high) for message length */
    uint8_t  buffer[SHA256_BLOCK_SIZE]; /**< Input buffer for partial blocks */
} sha256_ctx;

/**
 * @brief Initialize SHA-256 context
 *
 * Sets up the context with initial hash values as defined in FIPS 180-4.
 * Must be called before sha256_update().
 *
 * @param[out] ctx  Pointer to SHA-256 context to initialize
 */
void sha256_init(sha256_ctx* ctx);

/**
 * @brief Update hash with input data
 *
 * Processes input data and updates the hash state.
 * Can be called multiple times to hash data in chunks.
 *
 * @param[in,out] ctx   Pointer to initialized SHA-256 context
 * @param[in]     data  Pointer to input data
 * @param[in]     len   Length of input data in bytes
 */
void sha256_update(sha256_ctx* ctx, const uint8_t* data, size_t len);

/**
 * @brief Finalize hash and output result
 *
 * Applies padding, processes the final block, and outputs the hash.
 * The context is cleared after this call for security.
 *
 * @param[in,out] ctx   Pointer to SHA-256 context
 * @param[out]    hash  Output buffer for 32-byte hash result
 *
 * @note After calling this function, ctx is zeroed and must be
 *       re-initialized with sha256_init() before reuse.
 */
void sha256_final(sha256_ctx* ctx, uint8_t hash[SHA256_HASH_SIZE]);

/**
 * @brief Compute SHA-256 hash in one call
 *
 * Convenience function that hashes data in a single operation.
 * Equivalent to calling sha256_init(), sha256_update(), sha256_final().
 *
 * @param[in]  data  Pointer to input data
 * @param[in]  len   Length of input data in bytes
 * @param[out] hash  Output buffer for 32-byte hash result
 */
void sha256(const uint8_t* data, size_t len, uint8_t hash[SHA256_HASH_SIZE]);

#endif /* SHA256_H */
