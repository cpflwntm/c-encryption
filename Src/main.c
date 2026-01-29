/**
 * @file main.c
 * @brief RSA 3072 Signature Verification and AES-256-CBC Decryption Test
 *
 * This program runs tests for:
 *
 *   1. RSA 3072 Signature Verification:
 *      - Static Test: Uses pre-generated test data files
 *      - Dynamic Test: Generates random RSA 3072 key pairs and signatures
 *        using OpenSSL, then verifies them using the minimal rsa3072 library.
 *
 *   2. AES-256-CBC Decryption:
 *      - Dynamic Test: Generates random key/IV/plaintext, encrypts with OpenSSL,
 *        then decrypts using the minimal aes256cbc library.
 *
 * Build:
 *   make
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "rsa3072/rsa3072.h"
#include "aes256cbc/aes256cbc.h"

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>


/*============================================================================*/
/* Constants                                                                  */
/*============================================================================*/

/* Return codes */
#define RET_SUCCESS             0
#define RET_FAILURE             1
#define RET_ERR_PUBKEY_SIZE     (-1)
#define RET_ERR_SIG_SIZE        (-2)
#define RET_ERR_VERIFY          (-3)

/* RSA 3072 key size */
#define RSA_KEY_SIZE_BYTES      384

/* Maximum message size (16 KiB) */
#define MAX_MESSAGE_SIZE        (16 * 1024)

/* File paths for static test */
#define PATH_PUBLIC_N           "test/public_n.bin"
#define PATH_MESSAGE            "test/message.bin"
#define PATH_SIGNATURE          "test/signature.bin"

/* OpenSSL RSA test constants */
#define RSA_BITS                3072
#define RSA_BYTES               (RSA_BITS / 8)  /* 384 */
#define MESSAGE_SIZE            (256 * 1024)
#define PUBLIC_EXPONENT         65537

/* AES-256-CBC test constants */
#define AES_TEST_DATA_SIZE      (64 * 1024)     /* 64 KiB (must be 16-byte aligned) */

/* Test count */
#define RSA_LOOP_TEST_COUNT     100
#define AES_LOOP_TEST_COUNT     100

/* MSVC prior to VS2015 does not provide snprintf */
#if defined(_MSC_VER) && (_MSC_VER < 1900)
#define snprintf                _snprintf
#endif


/*============================================================================*/
/* Test Statistics                                                            */
/*============================================================================*/

typedef struct {
    /* RSA Static test results */
    int static_total;
    int static_passed;
    int static_failed;
    int static_valid_sig_pass;
    int static_valid_sig_fail;
    int static_corrupt_msg_pass;
    int static_corrupt_msg_fail;
    int static_corrupt_sig_pass;
    int static_corrupt_sig_fail;

    /* RSA Dynamic test results */
    int dynamic_total;
    int dynamic_passed;
    int dynamic_failed;
    int dynamic_valid_sig_pass;
    int dynamic_valid_sig_fail;
    int dynamic_corrupt_msg_pass;
    int dynamic_corrupt_msg_fail;
    int dynamic_corrupt_sig_pass;
    int dynamic_corrupt_sig_fail;
} rsa_stats_t;


typedef struct {
    /* AES Dynamic test results */
    int total;
    int passed;
    int failed;
    int decrypt_pass;
    int decrypt_fail;
    int corrupt_key_pass;
    int corrupt_key_fail;
    int corrupt_iv_pass;
    int corrupt_iv_fail;
    int corrupt_data_pass;
    int corrupt_data_fail;
} aes_stats_t;


/*============================================================================*/
/* Helper Functions                                                           */
/*============================================================================*/

/**
 * @brief Print hex dump with offset
 */
static void
print_hex                      (const char*             p_label,
                                const uint8_t*          p_data,
                                size_t                  len,
                                size_t                  max_print)
{
    size_t                      i;
    size_t                      print_len;

    print_len = (max_print > 0 && max_print < len) ? max_print : len;

    printf("%s (%zu bytes):\n", p_label, len);

    for (i = 0; i < print_len; i++)
    {
        if ((i % 16) == 0)
        {
            printf("  %04zX: ", i);
        }

        printf("%02X ", p_data[i]);

        if (((i + 1) % 16) == 0)
        {
            printf("\n");
        }
    }

    if ((print_len % 16) != 0)
    {
        printf("\n");
    }

    if (print_len < len)
    {
        printf("  ... (%zu more bytes)\n", len - print_len);
    }

    printf("\n");
}


/**
 * @brief Read file into buffer
 */
static int
read_file                      (const char*             p_path,
                                uint8_t*                p_buf,
                                size_t                  buf_size,
                                size_t*                 p_read_len)
{
    FILE*                       fp;
    size_t                      file_size;
    size_t                      read_len;

    if ((p_path == NULL) || (p_buf == NULL) || (p_read_len == NULL))
    {
        return RET_FAILURE;
    }

    *p_read_len = 0;

    fp = fopen(p_path, "rb");
    if (fp == NULL)
    {
        printf("ERROR: Cannot open file '%s'\n", p_path);
        return RET_FAILURE;
    }

    fseek(fp, 0, SEEK_END);
    file_size = (size_t)ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (file_size > buf_size)
    {
        printf("ERROR: File too large (%zu > %zu)\n", file_size, buf_size);
        fclose(fp);
        return RET_FAILURE;
    }

    read_len = fread(p_buf, 1, file_size, fp);
    fclose(fp);

    if (read_len != file_size)
    {
        printf("ERROR: Read incomplete (%zu / %zu)\n", read_len, file_size);
        return RET_FAILURE;
    }

    *p_read_len = read_len;
    return RET_SUCCESS;
}


/**
 * @brief Generate random bytes
 */
static void
generate_random_bytes          (uint8_t*                buf,
                                size_t                  len)
{
    RAND_bytes(buf, (int)len);
}


/**
 * @brief Generate RSA 3072 key pair using OpenSSL EVP API
 *
 * @param[out] pkey  Pointer to store generated key
 * @return           1 on success, 0 on failure
 */
static int
generate_keypair               (EVP_PKEY**              pkey)
{
    EVP_PKEY_CTX*               ctx;
    int                         ret;

    ctx = NULL;
    ret = 0;

    /* Create context for RSA key generation */
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (ctx == NULL)
    {
        printf("ERROR: EVP_PKEY_CTX_new_id failed\n");
        goto cleanup;
    }

    /* Initialize key generation */
    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        printf("ERROR: EVP_PKEY_keygen_init failed\n");
        goto cleanup;
    }

    /* Set RSA key size to 3072 bits */
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_BITS) <= 0)
    {
        printf("ERROR: EVP_PKEY_CTX_set_rsa_keygen_bits failed\n");
        goto cleanup;
    }

    /* Generate key pair */
    if (EVP_PKEY_keygen(ctx, pkey) <= 0)
    {
        printf("ERROR: EVP_PKEY_keygen failed\n");
        goto cleanup;
    }

    ret = 1;

cleanup:
    if (ctx != NULL)
    {
        EVP_PKEY_CTX_free(ctx);
    }

    return ret;
}


/**
 * @brief Extract public modulus N from EVP_PKEY
 *
 * @param[in]  pkey     RSA key pair
 * @param[out] n_bytes  384-byte buffer for modulus N (big-endian)
 * @return              1 on success, 0 on failure
 */
static int
extract_public_n               (EVP_PKEY*               pkey,
                                uint8_t*                n_bytes)
{
    BIGNUM*                     bn_n;
    int                         ret;
    int                         n_len;

    bn_n = NULL;
    ret  = 0;

    /* Get modulus N from key */
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &bn_n) <= 0)
    {
        printf("ERROR: EVP_PKEY_get_bn_param failed\n");
        goto cleanup;
    }

    /* Check size */
    n_len = BN_num_bytes(bn_n);
    if (n_len > RSA_BYTES)
    {
        printf("ERROR: Modulus too large (%d bytes)\n", n_len);
        goto cleanup;
    }

    /* Convert to big-endian bytes with zero padding */
    memset(n_bytes, 0, RSA_BYTES);
    BN_bn2binpad(bn_n, n_bytes, RSA_BYTES);

    ret = 1;

cleanup:
    if (bn_n != NULL)
    {
        BN_free(bn_n);
    }

    return ret;
}


/**
 * @brief Sign message using RSA PKCS#1 v1.5 with SHA-256
 *
 * @param[in]  pkey     RSA key pair (with private key)
 * @param[in]  msg      Message to sign
 * @param[in]  msg_len  Message length
 * @param[out] sig      384-byte buffer for signature
 * @return              1 on success, 0 on failure
 */
static int
sign_message                   (EVP_PKEY*               pkey,
                                const uint8_t*          msg,
                                size_t                  msg_len,
                                uint8_t*                sig)
{
    EVP_MD_CTX*                 md_ctx;
    EVP_PKEY_CTX*               pkey_ctx;
    size_t                      sig_len;
    int                         ret;

    md_ctx   = NULL;
    pkey_ctx = NULL;
    sig_len  = RSA_BYTES;
    ret      = 0;

    /* Create message digest context */
    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL)
    {
        printf("ERROR: EVP_MD_CTX_new failed\n");
        goto cleanup;
    }

    /* Initialize signing with SHA-256 and PKCS#1 v1.5 padding */
    if (EVP_DigestSignInit(md_ctx, &pkey_ctx, EVP_sha256(), NULL, pkey) <= 0)
    {
        printf("ERROR: EVP_DigestSignInit failed\n");
        goto cleanup;
    }

    /* Set PKCS#1 v1.5 padding (default, but explicit) */
    if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PADDING) <= 0)
    {
        printf("ERROR: EVP_PKEY_CTX_set_rsa_padding failed\n");
        goto cleanup;
    }

    /* Update with message data */
    if (EVP_DigestSignUpdate(md_ctx, msg, msg_len) <= 0)
    {
        printf("ERROR: EVP_DigestSignUpdate failed\n");
        goto cleanup;
    }

    /* Finalize signature */
    if (EVP_DigestSignFinal(md_ctx, sig, &sig_len) <= 0)
    {
        printf("ERROR: EVP_DigestSignFinal failed\n");
        goto cleanup;
    }

    /* Verify signature length */
    if (sig_len != RSA_BYTES)
    {
        printf("ERROR: Unexpected signature length (%zu)\n", sig_len);
        goto cleanup;
    }

    ret = 1;

cleanup:
    if (md_ctx != NULL)
    {
        EVP_MD_CTX_free(md_ctx);
    }

    return ret;
}


/*============================================================================*/
/* Test Functions                                                             */
/*============================================================================*/

/**
 * @brief Run static test using pre-generated test data files
 *
 * @param[in,out] rsa_stats  Test statistics (updated on return)
 * @return               RET_SUCCESS on success, error code on failure
 */
static int
run_static_test                (rsa_stats_t*            rsa_stats)
{
    int                         ret;
    static uint8_t              public_n[RSA_KEY_SIZE_BYTES];
    static uint8_t              message[MAX_MESSAGE_SIZE];
    static uint8_t              signature[RSA_KEY_SIZE_BYTES];
    size_t                      public_n_len;
    size_t                      message_len;
    size_t                      signature_len;

    printf("======================================================================\n");
    printf(" RSA 3072 Signature Verification - Static Test\n");
    printf("======================================================================\n\n");

    /* Load public modulus N */
    printf("[1] Loading public key modulus: %s\n", PATH_PUBLIC_N);

    ret = read_file(PATH_PUBLIC_N, public_n, RSA_KEY_SIZE_BYTES, &public_n_len);
    if (ret != RET_SUCCESS)
    {
        printf("    FAILED: Cannot read public key\n");
        return RET_FAILURE;
    }
    if (public_n_len != RSA_KEY_SIZE_BYTES)
    {
        printf("    FAILED: Invalid size (%zu, expected %d)\n",
               public_n_len, RSA_KEY_SIZE_BYTES);
        return RET_ERR_PUBKEY_SIZE;
    }
    printf("    OK: %zu bytes loaded\n\n", public_n_len);
    print_hex("Public Modulus N (first 64 bytes)", public_n, public_n_len, 64);

    /* Load message */
    printf("[2] Loading message: %s\n", PATH_MESSAGE);

    ret = read_file(PATH_MESSAGE, message, MAX_MESSAGE_SIZE, &message_len);
    if (ret != RET_SUCCESS)
    {
        printf("    FAILED: Cannot read message\n");
        return RET_FAILURE;
    }
    printf("    OK: %zu bytes loaded\n\n", message_len);
    print_hex("Message (first 64 bytes)", message, message_len, 64);

    /* Load signature */
    printf("[3] Loading signature: %s\n", PATH_SIGNATURE);

    ret = read_file(PATH_SIGNATURE, signature, RSA_KEY_SIZE_BYTES, &signature_len);
    if (ret != RET_SUCCESS)
    {
        printf("    FAILED: Cannot read signature\n");
        return RET_FAILURE;
    }
    if (signature_len != RSA_KEY_SIZE_BYTES)
    {
        printf("    FAILED: Invalid size (%zu, expected %d)\n",
               signature_len, RSA_KEY_SIZE_BYTES);
        return RET_ERR_SIG_SIZE;
    }
    printf("    OK: %zu bytes loaded\n\n", signature_len);
    print_hex("Signature (first 64 bytes)", signature, signature_len, 64);

    /* Verify signature using rsa3072 library */
    printf("[4] Verifying signature with rsa3072 library...\n");

    ret = rsa3072_verify(public_n, message, message_len, signature);

    if (ret == RSA3072_OK)
    {
        printf("    *** SIGNATURE VALID ***\n\n");
        rsa_stats->static_valid_sig_pass++;
        rsa_stats->static_passed++;
    }
    else if (ret == RSA3072_ERR_PARAM)
    {
        printf("    FAILED: Invalid parameter (error code: %d)\n\n", ret);
        rsa_stats->static_valid_sig_fail++;
        rsa_stats->static_failed++;
        return RET_ERR_VERIFY;
    }
    else
    {
        printf("    FAILED: Signature verification failed (error code: %d)\n\n", ret);
        rsa_stats->static_valid_sig_fail++;
        rsa_stats->static_failed++;
        return RET_ERR_VERIFY;
    }

    /* Test with corrupted message */
    printf("[5] Testing with corrupted message (expect FAIL)...\n");

    message[0] ^= 0xFF;  /* Flip bits in first byte */
    ret = rsa3072_verify(public_n, message, message_len, signature);
    message[0] ^= 0xFF;  /* Restore original */

    if (ret == RSA3072_OK)
    {
        printf("    UNEXPECTED: Corrupted message passed verification!\n\n");
        rsa_stats->static_corrupt_msg_fail++;
        rsa_stats->static_failed++;
        return RET_FAILURE;
    }
    else
    {
        printf("    OK: Corrupted message correctly rejected\n\n");
        rsa_stats->static_corrupt_msg_pass++;
        rsa_stats->static_passed++;
    }

    /* Test with corrupted signature */
    printf("[6] Testing with corrupted signature (expect FAIL)...\n");

    signature[0] ^= 0xFF;  /* Flip bits in first byte */
    ret = rsa3072_verify(public_n, message, message_len, signature);
    signature[0] ^= 0xFF;  /* Restore original */

    if (ret == RSA3072_OK)
    {
        printf("    UNEXPECTED: Corrupted signature passed verification!\n\n");
        rsa_stats->static_corrupt_sig_fail++;
        rsa_stats->static_failed++;
        return RET_FAILURE;
    }
    else
    {
        printf("    OK: Corrupted signature correctly rejected\n\n");
        rsa_stats->static_corrupt_sig_pass++;
        rsa_stats->static_passed++;
    }

    /* Update total count */
    rsa_stats->static_total += 3;

    return RET_SUCCESS;
}


/**
 * @brief Run single OpenSSL test iteration
 *
 * @param[in]     iteration  Current iteration number
 * @param[in,out] rsa_stats      Test statistics
 * @return                   1 if all tests passed, 0 otherwise
 */
static int
run_dynamic_test               (int                     iteration,
                                rsa_stats_t*            rsa_stats)
{
    EVP_PKEY*                   pkey;
    uint8_t                     public_n[RSA_BYTES];
    uint8_t                     message[MESSAGE_SIZE];
    uint8_t                     signature[RSA_BYTES];
    uint8_t                     corrupted_msg[MESSAGE_SIZE];
    uint8_t                     corrupted_sig[RSA_BYTES];
    int                         result;
    int                         all_passed;

    pkey       = NULL;
    all_passed = 1;

    printf("======================================================================\n");
    printf(" RSA 3072 Signature Verification - Dynamic Test(Iter. %d)\n", iteration + 1);
    printf("======================================================================\n\n");

    /*------------------------------------------------------------------------*/
    /* Step 1: Generate RSA 3072 key pair                                     */
    /*------------------------------------------------------------------------*/
    printf("[1] Generating RSA 3072 key pair...\n");

    if (!generate_keypair(&pkey))
    {
        printf("ERROR: Key generation failed\n");
        rsa_stats->dynamic_failed++;
        return 0;
    }

    /*------------------------------------------------------------------------*/
    /* Step 2: Extract public modulus N                                       */
    /*------------------------------------------------------------------------*/
    if (!extract_public_n(pkey, public_n))
    {
        printf("ERROR: Failed to extract public N\n");
        EVP_PKEY_free(pkey);
        rsa_stats->dynamic_failed++;
        return 0;
    }

    print_hex("[2] Extract Public modulus N", public_n, RSA_BYTES, 32);

    /*------------------------------------------------------------------------*/
    /* Step 3: Generate random message & Sign message with OpenSSL            */
    /*------------------------------------------------------------------------*/
    generate_random_bytes(message, MESSAGE_SIZE);
    print_hex("Message", message, MESSAGE_SIZE, 32);

    printf("[3] Signing message with OpenSSL...\n");

    if (!sign_message(pkey, message, MESSAGE_SIZE, signature))
    {
        printf("ERROR: Signing failed\n");
        EVP_PKEY_free(pkey);
        rsa_stats->dynamic_failed++;
        return 0;
    }

    print_hex("Signature", signature, RSA_BYTES, 32);

    /*------------------------------------------------------------------------*/
    /* Step 4: Valid signature (should PASS)                                  */
    /*------------------------------------------------------------------------*/
    printf("[4] Verifying signature with rsa3072 library...\n");

    result = rsa3072_verify(public_n, message, MESSAGE_SIZE, signature);

    if (result == RSA3072_OK)
    {
        printf("    *** SIGNATURE VALID ***\n\n");
        rsa_stats->dynamic_valid_sig_pass++;
        rsa_stats->dynamic_passed++;
    }
    else
    {
        printf("    FAILED: Signature verification failed (error code: %d)\n\n", result);
        rsa_stats->dynamic_valid_sig_fail++;
        rsa_stats->dynamic_failed++;
        all_passed = 0;

        /* Save failed case for debugging */
        {
            char filename[64];
            FILE* fp;
            snprintf(filename, sizeof(filename), "fail_%d.bin", iteration);
            fp = fopen(filename, "wb");
            if (fp)
            {
                fwrite(public_n, 1, RSA_BYTES, fp);
                fwrite(message, 1, MESSAGE_SIZE, fp);
                fwrite(signature, 1, RSA_BYTES, fp);
                fclose(fp);
                printf("    Saved failed case to %s\n", filename);
            }
        }
    }

    /*------------------------------------------------------------------------*/
    /* Step 5: Corrupted message (should FAIL)                                */
    /*------------------------------------------------------------------------*/
    printf("[5] Testing with corrupted message (expect FAIL)...\n");

    memcpy(corrupted_msg, message, MESSAGE_SIZE);
    corrupted_msg[0] ^= 0x01;  /* Flip one bit */

    result = rsa3072_verify(public_n, corrupted_msg, MESSAGE_SIZE, signature);

    if (result != RSA3072_OK)
    {
        printf("    OK: Corrupted message correctly rejected\n\n");
        rsa_stats->dynamic_corrupt_msg_pass++;
        rsa_stats->dynamic_passed++;
    }
    else
    {
        printf("    UNEXPECTED: Corrupted message passed verification!\n\n");
        rsa_stats->dynamic_corrupt_msg_fail++;
        rsa_stats->dynamic_failed++;
        all_passed = 0;
    }

    /*------------------------------------------------------------------------*/
    /* Step 6: Corrupted signature (should FAIL)                              */
    /*------------------------------------------------------------------------*/
    printf("[6] Testing with corrupted signature (expect FAIL)...\n");

    memcpy(corrupted_sig, signature, RSA_BYTES);
    corrupted_sig[RSA_BYTES - 1] ^= 0x01;  /* Flip one bit */

    result = rsa3072_verify(public_n, message, MESSAGE_SIZE, corrupted_sig);

    if (result != RSA3072_OK)
    {
        printf("    OK: Corrupted signature correctly rejected\n\n");
        rsa_stats->dynamic_corrupt_sig_pass++;
        rsa_stats->dynamic_passed++;
    }
    else
    {
        printf("    UNEXPECTED: Corrupted signature passed verification!\n\n");
        rsa_stats->dynamic_corrupt_sig_fail++;
        rsa_stats->dynamic_failed++;
        all_passed = 0;
    }

    /*------------------------------------------------------------------------*/
    /* Cleanup                                                                */
    /*------------------------------------------------------------------------*/
    EVP_PKEY_free(pkey);

    rsa_stats->dynamic_total += 3;

    return all_passed;
}


/**
 * @brief Print final test summary (static + dynamic)
 */
static void
print_rsa_result               (const rsa_stats_t*      rsa_stats,
                                int                     loop_count,
                                double                  elapsed_sec)
{
    int                         total_tests;
    int                         total_passed;
    int                         total_failed;

    total_tests  = rsa_stats->static_total + rsa_stats->dynamic_total;
    total_passed = rsa_stats->static_passed + rsa_stats->dynamic_passed;
    total_failed = rsa_stats->static_failed + rsa_stats->dynamic_failed;

    printf("\n");
    printf("======================================================================\n");
    printf(" RSA 3072 TEST SUMMARY\n");
    printf("======================================================================\n");

    /* Static test results */
    printf("\n");
    printf("--- Static Test ---\n");
    printf("Total tests:          %d\n", rsa_stats->static_total);
    printf("Passed:               %d\n", rsa_stats->static_passed);
    printf("Failed:               %d\n", rsa_stats->static_failed);
    printf("\n");
    printf("Breakdown:\n");
    printf("  Valid signature:      %d pass / %d fail\n",
           rsa_stats->static_valid_sig_pass, rsa_stats->static_valid_sig_fail);
    printf("  Corrupted message:    %d pass / %d fail\n",
           rsa_stats->static_corrupt_msg_pass, rsa_stats->static_corrupt_msg_fail);
    printf("  Corrupted signature:  %d pass / %d fail\n",
           rsa_stats->static_corrupt_sig_pass, rsa_stats->static_corrupt_sig_fail);

    /* Dynamic test results */
    printf("\n");
    printf("--- Dynamic Test (OpenSSL) ---\n");
    printf("Iterations:           %d\n", loop_count);
    printf("Total tests:          %d\n", rsa_stats->dynamic_total);
    printf("Passed:               %d\n", rsa_stats->dynamic_passed);
    printf("Failed:               %d\n", rsa_stats->dynamic_failed);
    printf("\n");
    printf("Breakdown:\n");
    printf("  Valid signature:      %d pass / %d fail\n",
           rsa_stats->dynamic_valid_sig_pass, rsa_stats->dynamic_valid_sig_fail);
    printf("  Corrupted message:    %d pass / %d fail\n",
           rsa_stats->dynamic_corrupt_msg_pass, rsa_stats->dynamic_corrupt_msg_fail);
    printf("  Corrupted signature:  %d pass / %d fail\n",
           rsa_stats->dynamic_corrupt_sig_pass, rsa_stats->dynamic_corrupt_sig_fail);
    printf("\n");
    printf("Elapsed time:         %.2f seconds\n", elapsed_sec);
    printf("Time per iteration:   %.2f seconds\n", elapsed_sec / loop_count);

    /* Overall summary */
    printf("\n");
    printf("--- Overall ---\n");
    printf("Total tests:          %d\n", total_tests);
    printf("Passed:               %d\n", total_passed);
    printf("Failed:               %d\n", total_failed);
    printf("\n");

    if (total_failed == 0)
    {
        printf("*** ALL TESTS PASSED ***\n");
    }
    else
    {
        printf("*** %d TESTS FAILED ***\n", total_failed);
    }

    printf("======================================================================\n");
}


/*============================================================================*/
/* AES-256-CBC Test Functions                                                 */
/*============================================================================*/

/**
 * @brief Encrypt data using OpenSSL AES-256-CBC (no padding)
 *
 * @param[in]  key         AES key (32 bytes)
 * @param[in]  iv          Initialization vector (16 bytes)
 * @param[in]  plaintext   Input data (must be 16-byte aligned)
 * @param[in]  len         Data length (must be multiple of 16)
 * @param[out] ciphertext  Output buffer (same size as plaintext)
 * @return                 1 on success, 0 on failure
 */
static int
aes256_cbc_encrypt_openssl     (const uint8_t*          key,
                                const uint8_t*          iv,
                                const uint8_t*          plaintext,
                                size_t                  len,
                                uint8_t*                ciphertext)
{
    EVP_CIPHER_CTX*             ctx;
    int                         out_len;
    int                         ret;

    ctx = NULL;
    ret = 0;

    /* Create context */
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        printf("ERROR: EVP_CIPHER_CTX_new failed\n");
        goto cleanup;
    }

    /* Initialize encryption (no padding) */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
    {
        printf("ERROR: EVP_EncryptInit_ex failed\n");
        goto cleanup;
    }

    /* Disable padding (input must be 16-byte aligned) */
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    /* Encrypt data */
    if (EVP_EncryptUpdate(ctx, ciphertext, &out_len, plaintext, (int)len) != 1)
    {
        printf("ERROR: EVP_EncryptUpdate failed\n");
        goto cleanup;
    }

    if ((size_t)out_len != len)
    {
        printf("ERROR: Unexpected output length (%d, expected %zu)\n", out_len, len);
        goto cleanup;
    }

    /* Finalize (should produce no additional output with no padding) */
    if (EVP_EncryptFinal_ex(ctx, ciphertext + out_len, &out_len) != 1)
    {
        printf("ERROR: EVP_EncryptFinal_ex failed\n");
        goto cleanup;
    }

    ret = 1;

cleanup:
    if (ctx != NULL)
    {
        EVP_CIPHER_CTX_free(ctx);
    }

    return ret;
}


/**
 * @brief Run single AES-256-CBC test iteration
 *
 * @param[in]     iteration  Current iteration number
 * @param[in,out] rsa_stats      Test statistics
 * @return                   1 if all tests passed, 0 otherwise
 */
static int
run_aes_test                   (int                     iteration,
                                aes_stats_t*            rsa_stats)
{
    uint8_t                     key[AES256_KEY_SIZE];
    uint8_t                     iv[AES256_IV_SIZE];
    static uint8_t              plaintext[AES_TEST_DATA_SIZE];
    static uint8_t              ciphertext[AES_TEST_DATA_SIZE];
    static uint8_t              decrypted[AES_TEST_DATA_SIZE];
    uint8_t                     corrupt_key[AES256_KEY_SIZE];
    uint8_t                     corrupt_iv[AES256_IV_SIZE];
    static uint8_t              corrupt_cipher[AES_TEST_DATA_SIZE];
    int                         result;
    int                         all_passed;

    all_passed = 1;

    printf("======================================================================\n");
    printf(" AES-256-CBC Decryption Test - Iteration %d\n", iteration + 1);
    printf("======================================================================\n\n");

    /*------------------------------------------------------------------------*/
    /* Step 1: Generate random key, IV, and plaintext                         */
    /*------------------------------------------------------------------------*/
    printf("[1] Generating random key, IV, and plaintext...\n");

    generate_random_bytes(key, AES256_KEY_SIZE);
    generate_random_bytes(iv, AES256_IV_SIZE);
    generate_random_bytes(plaintext, AES_TEST_DATA_SIZE);

    print_hex("Key", key, AES256_KEY_SIZE, 32);
    print_hex("IV", iv, AES256_IV_SIZE, 16);
    print_hex("Plaintext", plaintext, AES_TEST_DATA_SIZE, 32);

    /*------------------------------------------------------------------------*/
    /* Step 2: Encrypt with OpenSSL                                           */
    /*------------------------------------------------------------------------*/
    printf("[2] Encrypting with OpenSSL AES-256-CBC...\n");

    if (!aes256_cbc_encrypt_openssl(key, iv, plaintext, AES_TEST_DATA_SIZE, ciphertext))
    {
        printf("ERROR: OpenSSL encryption failed\n");
        rsa_stats->failed++;
        return 0;
    }

    print_hex("Ciphertext", ciphertext, AES_TEST_DATA_SIZE, 32);

    /*------------------------------------------------------------------------*/
    /* Step 3: Decrypt with aes256cbc library (should PASS)                   */
    /*------------------------------------------------------------------------*/
    printf("[3] Decrypting with aes256cbc library...\n");

    result = aes256_cbc_decrypt(key, iv, ciphertext, AES_TEST_DATA_SIZE, decrypted);

    if (result == AES256_OK)
    {
        /* Verify decrypted data matches original plaintext */
        if (memcmp(decrypted, plaintext, AES_TEST_DATA_SIZE) == 0)
        {
            printf("    *** DECRYPTION SUCCESSFUL ***\n\n");
            rsa_stats->decrypt_pass++;
            rsa_stats->passed++;
        }
        else
        {
            printf("    FAILED: Decrypted data does not match plaintext!\n\n");
            rsa_stats->decrypt_fail++;
            rsa_stats->failed++;
            all_passed = 0;
        }
    }
    else
    {
        printf("    FAILED: Decryption failed (error code: %d)\n\n", result);
        rsa_stats->decrypt_fail++;
        rsa_stats->failed++;
        all_passed = 0;
    }

    /*------------------------------------------------------------------------*/
    /* Step 4: Decrypt with wrong key (should produce different output)       */
    /*------------------------------------------------------------------------*/
    printf("[4] Testing with wrong key (expect different output)...\n");

    memcpy(corrupt_key, key, AES256_KEY_SIZE);
    corrupt_key[0] ^= 0x01;  /* Flip one bit */

    result = aes256_cbc_decrypt(corrupt_key, iv, ciphertext, AES_TEST_DATA_SIZE, decrypted);

    if (result == AES256_OK)
    {
        /* Decryption succeeds but output should be garbage */
        if (memcmp(decrypted, plaintext, AES_TEST_DATA_SIZE) != 0)
        {
            printf("    OK: Wrong key produces different output\n\n");
            rsa_stats->corrupt_key_pass++;
            rsa_stats->passed++;
        }
        else
        {
            printf("    UNEXPECTED: Wrong key produced correct plaintext!\n\n");
            rsa_stats->corrupt_key_fail++;
            rsa_stats->failed++;
            all_passed = 0;
        }
    }
    else
    {
        /* This shouldn't happen since input is valid */
        printf("    WARNING: Decryption error with wrong key (code: %d)\n\n", result);
        rsa_stats->corrupt_key_pass++;
        rsa_stats->passed++;
    }

    /*------------------------------------------------------------------------*/
    /* Step 5: Decrypt with wrong IV (should produce different first block)   */
    /*------------------------------------------------------------------------*/
    printf("[5] Testing with wrong IV (expect different first block)...\n");

    memcpy(corrupt_iv, iv, AES256_IV_SIZE);
    corrupt_iv[0] ^= 0x01;  /* Flip one bit */

    result = aes256_cbc_decrypt(key, corrupt_iv, ciphertext, AES_TEST_DATA_SIZE, decrypted);

    if (result == AES256_OK)
    {
        /* First block should be wrong, rest should be correct (CBC property) */
        if (memcmp(decrypted, plaintext, AES256_BLOCK_SIZE) != 0)
        {
            printf("    OK: Wrong IV produces different first block\n\n");
            rsa_stats->corrupt_iv_pass++;
            rsa_stats->passed++;
        }
        else
        {
            printf("    UNEXPECTED: Wrong IV produced correct first block!\n\n");
            rsa_stats->corrupt_iv_fail++;
            rsa_stats->failed++;
            all_passed = 0;
        }
    }
    else
    {
        printf("    WARNING: Decryption error with wrong IV (code: %d)\n\n", result);
        rsa_stats->corrupt_iv_pass++;
        rsa_stats->passed++;
    }

    /*------------------------------------------------------------------------*/
    /* Step 6: Decrypt corrupted ciphertext (should produce different output) */
    /*------------------------------------------------------------------------*/
    printf("[6] Testing with corrupted ciphertext (expect different output)...\n");

    memcpy(corrupt_cipher, ciphertext, AES_TEST_DATA_SIZE);
    corrupt_cipher[0] ^= 0x01;  /* Flip one bit in first block */

    result = aes256_cbc_decrypt(key, iv, corrupt_cipher, AES_TEST_DATA_SIZE, decrypted);

    if (result == AES256_OK)
    {
        /* First two blocks should be affected (current and next due to CBC) */
        if (memcmp(decrypted, plaintext, AES256_BLOCK_SIZE) != 0)
        {
            printf("    OK: Corrupted ciphertext produces different output\n\n");
            rsa_stats->corrupt_data_pass++;
            rsa_stats->passed++;
        }
        else
        {
            printf("    UNEXPECTED: Corrupted ciphertext produced correct output!\n\n");
            rsa_stats->corrupt_data_fail++;
            rsa_stats->failed++;
            all_passed = 0;
        }
    }
    else
    {
        printf("    WARNING: Decryption error with corrupted data (code: %d)\n\n", result);
        rsa_stats->corrupt_data_pass++;
        rsa_stats->passed++;
    }

    /*------------------------------------------------------------------------*/
    /* Update total count                                                     */
    /*------------------------------------------------------------------------*/
    rsa_stats->total += 4;

    return all_passed;
}


/**
 * @brief Print AES test summary
 */
static void
print_aes_result               (const aes_stats_t*      rsa_stats,
                                int                     loop_count,
                                double                  elapsed_sec)
{
    printf("\n");
    printf("======================================================================\n");
    printf(" AES-256-CBC TEST SUMMARY\n");
    printf("======================================================================\n");
    printf("\n");
    printf("Iterations:           %d\n", loop_count);
    printf("Total tests:          %d\n", rsa_stats->total);
    printf("Passed:               %d\n", rsa_stats->passed);
    printf("Failed:               %d\n", rsa_stats->failed);
    printf("\n");
    printf("Breakdown:\n");
    printf("  Decrypt OK:           %d pass / %d fail\n",
           rsa_stats->decrypt_pass, rsa_stats->decrypt_fail);
    printf("  Wrong key:            %d pass / %d fail\n",
           rsa_stats->corrupt_key_pass, rsa_stats->corrupt_key_fail);
    printf("  Wrong IV:             %d pass / %d fail\n",
           rsa_stats->corrupt_iv_pass, rsa_stats->corrupt_iv_fail);
    printf("  Corrupted data:       %d pass / %d fail\n",
           rsa_stats->corrupt_data_pass, rsa_stats->corrupt_data_fail);
    printf("\n");
    printf("Elapsed time:         %.2f seconds\n", elapsed_sec);
    printf("Time per iteration:   %.4f seconds\n", elapsed_sec / loop_count);
    printf("\n");

    if (rsa_stats->failed == 0)
    {
        printf("*** ALL AES TESTS PASSED ***\n");
    }
    else
    {
        printf("*** %d AES TESTS FAILED ***\n", rsa_stats->failed);
    }

    printf("======================================================================\n");
}


/*============================================================================*/
/* Main Function                                                              */
/*============================================================================*/
int
main                           (void)
{
    aes_stats_t                 aes_stats;
    clock_t                     aes_start;
    clock_t                     aes_end;
    rsa_stats_t                 rsa_stats;
    clock_t                     rsa_start;
    clock_t                     rsa_end;
    double                      aes_elapsed_sec;
    double                      rsa_elapsed_sec;
    int                         i;
    int                         ret;

    /* Initialize statistics */
    memset(&rsa_stats, 0, sizeof(rsa_stats));

    /*------------------------------------------------------------------------*/
    /* Part 1: Static Test (using test/ folder data)                          */
    /*------------------------------------------------------------------------*/
    ret = run_static_test(&rsa_stats);
    if (ret != RET_SUCCESS)
    {
        printf("Static test failed with error code: %d\n", ret);
        return ret;
    }

    /*------------------------------------------------------------------------*/
    /* Part 2: Dynamic Test (random key generation)                           */
    /*------------------------------------------------------------------------*/
    printf("\n");
    printf("======================================================================\n");
    printf(" RSA 3072 Dynamic Signature Verification Test (OpenSSL)\n");
    printf("======================================================================\n");
    printf("\n");

    /* Print header */
    printf("\n");
    printf("Loop count:     %d\n", RSA_LOOP_TEST_COUNT);
    printf("RSA key size:   %d bits\n", RSA_BITS);
    printf("Message size:   %d bytes\n", MESSAGE_SIZE);
    printf("OpenSSL:        %s\n", OpenSSL_version(OPENSSL_VERSION));
    printf("\n");
    printf("Tests per iteration:\n");
    printf("  1. Valid signature       -> Expected: PASS\n");
    printf("  2. Corrupted message     -> Expected: FAIL\n");
    printf("  3. Corrupted signature   -> Expected: FAIL\n\n");

    /* Record start time */
    rsa_start = clock();

    /* Run test iterations */
    for (i = 0; i < RSA_LOOP_TEST_COUNT; i++)
    {
        run_dynamic_test(i, &rsa_stats);
    }

    /* Record end time */
    rsa_end = clock();
    rsa_elapsed_sec = (double)(rsa_end - rsa_start) / CLOCKS_PER_SEC;

    /*------------------------------------------------------------------------*/
    /* Part 3: AES-256-CBC Decryption Test                                    */
    /*------------------------------------------------------------------------*/
    memset(&aes_stats, 0, sizeof(aes_stats));

    printf("\n");
    printf("======================================================================\n");
    printf(" AES-256-CBC Decryption Test (OpenSSL Encrypt -> aes256cbc Decrypt)\n");
    printf("======================================================================\n");
    printf("\n");
    printf("Loop count:     %d\n", AES_LOOP_TEST_COUNT);
    printf("Data size:      %d bytes\n", AES_TEST_DATA_SIZE);
    printf("Key size:       %d bytes (256 bits)\n", AES256_KEY_SIZE);
    printf("Block size:     %d bytes\n", AES256_BLOCK_SIZE);
    printf("\n");
    printf("Tests per iteration:\n");
    printf("  1. Valid decryption      -> Expected: PASS\n");
    printf("  2. Wrong key             -> Expected: Different output\n");
    printf("  3. Wrong IV              -> Expected: Different first block\n");
    printf("  4. Corrupted ciphertext  -> Expected: Different output\n\n");

    /* Record start time */
    aes_start = clock();

    /* Run AES test iterations */
    for (i = 0; i < AES_LOOP_TEST_COUNT; i++)
    {
        run_aes_test(i, &aes_stats);
    }

    /* Record end time */
    aes_end = clock();
    aes_elapsed_sec = (double)(aes_end - aes_start) / CLOCKS_PER_SEC;

    /* Print RSA summary */
    print_rsa_result(&rsa_stats, RSA_LOOP_TEST_COUNT, rsa_elapsed_sec);

    /* Print AES summary */
    print_aes_result(&aes_stats, AES_LOOP_TEST_COUNT, aes_elapsed_sec);

    /*------------------------------------------------------------------------*/
    /* Final Summary                                                          */
    /*------------------------------------------------------------------------*/
    printf("\n");
    printf("======================================================================\n");
    printf(" ALL TESTS COMPLETED\n");
    printf("======================================================================\n");

    return RET_SUCCESS;
}
