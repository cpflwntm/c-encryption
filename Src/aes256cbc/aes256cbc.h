/**
 * @file aes256cbc.h
 * @brief Minimal AES-256-CBC Decryption
 *
 * AES-256-CBC decryption without padding.
 * Size-optimized for embedded systems (~2 KB total).
 *
 * Features:
 * - AES 256-bit key support (32 bytes)
 * - CBC mode decryption
 * - No padding (input must be 16-byte aligned)
 * - Constant-time implementation
 *
 * @note Code size: ~2 KB (ARM Thumb-2, -Os)
 * @note Stack usage: ~500 bytes (round keys + temporaries)
 * @note No dynamic memory allocation
 */

#ifndef AES256CBC_H
#define AES256CBC_H

#include <stdint.h>
#include <stddef.h>


/*============================================================================*/
/* Constants                                                                  */
/*============================================================================*/

/**
 * @def AES256_BLOCK_SIZE
 * @brief AES block size in bytes (128 bits)
 */
#define AES256_BLOCK_SIZE       16

/**
 * @def AES256_KEY_SIZE
 * @brief AES-256 key size in bytes (256 bits)
 */
#define AES256_KEY_SIZE         32

/**
 * @def AES256_IV_SIZE
 * @brief AES IV size in bytes (same as block size)
 */
#define AES256_IV_SIZE          16

/**
 * @def AES256_ROUNDS
 * @brief Number of AES-256 rounds
 */
#define AES256_ROUNDS           14


/*============================================================================*/
/* Return Codes                                                               */
/*============================================================================*/

/**
 * @def AES256_OK
 * @brief Success return code
 */
#define AES256_OK               0

/**
 * @def AES256_ERR_PARAM
 * @brief Error: Invalid parameter (NULL pointer)
 */
#define AES256_ERR_PARAM        (-1)

/**
 * @def AES256_ERR_LENGTH
 * @brief Error: Invalid length (not multiple of 16)
 */
#define AES256_ERR_LENGTH       (-2)


/*============================================================================*/
/* Public API                                                                 */
/*============================================================================*/

/**
 * @brief Decrypt data using AES-256-CBC mode (no padding)
 *
 * Decrypts ciphertext using AES-256 in CBC mode.
 * Input length must be a multiple of 16 bytes.
 *
 * CBC Decryption:
 *   P[0] = AES_Decrypt(C[0]) XOR IV
 *   P[i] = AES_Decrypt(C[i]) XOR C[i-1]  for i > 0
 *
 * @param[in]  p_key         Encryption key (32 bytes)
 * @param[in]  p_iv          Initialization vector (16 bytes)
 * @param[in]  p_ciphertext  Encrypted data (must be 16-byte aligned)
 * @param[in]  len           Data length in bytes (must be multiple of 16)
 * @param[out] p_plaintext   Output buffer (same size as ciphertext)
 *                           May overlap with p_ciphertext for in-place decryption
 *
 * @return AES256_OK         Success
 * @return AES256_ERR_PARAM  Invalid parameter (NULL pointer)
 * @return AES256_ERR_LENGTH Invalid length (not multiple of 16)
 *
 * @note All sensitive data is cleared from stack before returning
 *
 * Example usage:
 * @code
 * uint8_t key[32] = { ... };        // AES-256 key
 * uint8_t iv[16] = { ... };         // Initialization vector
 * uint8_t ciphertext[64] = { ... }; // Encrypted data (4 blocks)
 * uint8_t plaintext[64];            // Output buffer
 *
 * int result = aes256_cbc_decrypt(key, iv, ciphertext, 64, plaintext);
 * if (result == AES256_OK) {
 *     // Decryption successful
 * }
 * @endcode
 */
int aes256_cbc_decrypt(const uint8_t* p_key,
                       const uint8_t* p_iv,
                       const uint8_t* p_ciphertext,
                       size_t         len,
                       uint8_t*       p_plaintext);

#endif /* AES256CBC_H */
