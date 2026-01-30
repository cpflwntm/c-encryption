/**
 * @file rsa3072.h
 * @brief Minimal RSA 3072 Signature Verification
 *
 * RSA-SHA256 signature verification with PKCS#1 v1.5 padding.
 * Size-optimized for embedded systems (~3.4 KB total).
 *
 * Features:
 * - RSA 3072-bit key support (384 bytes)
 * - Fixed public exponent E = 65537 (0x10001)
 * - SHA-256 message digest
 * - PKCS#1 v1.5 signature padding
 * - Constant-time comparison for security
 *
 * @note Code size: ~3.4 KB (ARM Thumb-2, -Os) including SHA-256
 * @note Stack usage: ~1.7 KB (CIOS Montgomery + SHA-256 context)
 * @note No dynamic memory allocation
 */

#ifndef RSA3072_H
#define RSA3072_H

#include <stdint.h>
#include <stddef.h>


/*============================================================================*/
/* Constants                                                                  */
/*============================================================================*/

/**
 * @def RSA3072_KEY_BYTES
 * @brief RSA 3072 key size in bytes (3072 bits / 8)
 */
#define RSA3072_KEY_BYTES   384

/**
 * @def RSA3072_KEY_BITS
 * @brief RSA 3072 key size in bits
 */
#define RSA3072_KEY_BITS    3072


/*============================================================================*/
/* Return Codes                                                               */
/*============================================================================*/

/**
 * @def RSA3072_OK
 * @brief Success return code (signature is valid)
 */
#define RSA3072_OK          0

/**
 * @def RSA3072_ERR_PARAM
 * @brief Error: Invalid parameter (NULL pointer)
 */
#define RSA3072_ERR_PARAM   (-1)

/**
 * @def RSA3072_ERR_VERIFY
 * @brief Error: Signature verification failed
 *
 * This can mean:
 * - Signature is invalid (corrupted or forged)
 * - Wrong public key used
 * - Message was modified after signing
 * - PKCS#1 v1.5 padding is incorrect
 */
#define RSA3072_ERR_VERIFY  (-2)


/*============================================================================*/
/* Public API                                                                 */
/*============================================================================*/

/**
 * @brief Verify RSA 3072 PKCS#1 v1.5 signature with SHA-256
 *
 * Verifies that the given signature is a valid RSA-SHA256 signature
 * for the given message, using the provided public key.
 *
 * Algorithm:
 * 1. Compute SHA-256 hash of the message
 * 2. Perform RSA public key operation: decrypted = signature^65537 mod N
 * 3. Verify PKCS#1 v1.5 padding structure
 * 4. Compare extracted hash with computed hash (constant-time)
 *
 * @param[in] p_public_n   Public modulus N (384 bytes, big-endian)
 *                         Must be a valid RSA modulus (odd, > 1)
 * @param[in] p_message    Message data to verify
 * @param[in] message_len  Length of message in bytes (can be 0 to 2^32-1)
 * @param[in] p_signature  Signature to verify (384 bytes, big-endian)
 *                         Must satisfy 0 <= signature < N
 *
 * @return RSA3072_OK          Signature is valid
 * @return RSA3072_ERR_PARAM   Invalid parameter (NULL pointer)
 * @return RSA3072_ERR_VERIFY  Signature verification failed
 *
 * @note Public exponent E is fixed at 65537 (0x10001)
 * @note All sensitive data is cleared from stack before returning
 *
 * Example usage:
 * @code
 * uint8_t public_n[384] = { ... };  // RSA public modulus
 * uint8_t message[] = "Hello";      // Message to verify
 * uint8_t signature[384] = { ... }; // RSA signature
 *
 * int result = rsa3072_verify(public_n, message, sizeof(message)-1, signature);
 * if (result == RSA3072_OK) {
 *     // Signature is valid
 * } else {
 *     // Signature is invalid or error occurred
 * }
 * @endcode
 */
int rsa3072_verify(const uint8_t* p_public_n,
                   const uint8_t* p_message,
                   size_t         message_len,
                   const uint8_t* p_signature);

#endif /* RSA3072_H */
