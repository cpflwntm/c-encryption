/**
 * @file aes256cbc.c
 * @brief Minimal AES-256-CBC Decryption Implementation
 *
 * Size-optimized AES-256-CBC decryption for embedded systems.
 * Uses computation-based approach for InvMixColumns to minimize ROM usage.
 */

#include "aes256cbc.h"
#include <string.h>


/*============================================================================*/
/* Internal Constants                                                         */
/*============================================================================*/

/* Number of 32-bit words in key (AES-256 = 8) */
#define NK              8

/* Number of 32-bit words in block (always 4 for AES) */
#define NB              4

/* Number of rounds (AES-256 = 14) */
#define NR              14

/* Expanded key size in 32-bit words */
#define KEY_EXP_SIZE    (NB * (NR + 1))  /* 4 * 15 = 60 words = 240 bytes */


/*============================================================================*/
/* AES S-box (for key expansion)                                              */
/*============================================================================*/

static const uint8_t g_sbox[256] =
{
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};


/*============================================================================*/
/* AES Inverse S-box (for decryption)                                         */
/*============================================================================*/

static const uint8_t g_inv_sbox[256] =
{
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
    0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
    0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D,
    0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2,
    0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA,
    0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A,
    0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
    0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA,
    0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85,
    0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89,
    0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20,
    0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31,
    0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
    0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0,
    0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26,
    0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};


/*============================================================================*/
/* Round Constants (for key expansion)                                        */
/*============================================================================*/

static const uint8_t g_rcon[11] =
{
    0x00,  /* not used */
    0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1B, 0x36
};


/*============================================================================*/
/* Internal Functions                                                         */
/*============================================================================*/
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


/*============================================================================*/
/* GF(2^8) Multiplication Helpers                                             */
/*============================================================================*/

/**
 * @brief Multiply two values in GF(2^8)
 *
 * Uses Russian peasant multiplication algorithm.
 */
static uint8_t
gf_mul                         (uint8_t                 a,
                                uint8_t                 b)
{
    uint8_t                     p;
    uint8_t                     hi_bit;
    int                         i;

    p = 0;

    for (i = 0; i < 8; i++)
    {
        if (b & 1)
        {
            p ^= a;
        }

        hi_bit = a & 0x80;
        a <<= 1;

        if (hi_bit)
        {
            a ^= 0x1B;  /* AES irreducible polynomial */
        }

        b >>= 1;
    }

    return p;
}


/*============================================================================*/
/* Key Expansion                                                              */
/*============================================================================*/

/**
 * @brief Expand AES-256 key to round keys
 *
 * @param[out] round_keys  Output buffer for expanded keys (240 bytes)
 * @param[in]  key         Original key (32 bytes)
 */
static void
key_expansion                  (uint32_t*               round_keys,
                                const uint8_t*          key)
{
    uint32_t                    temp;
    int                         i;

    /* First 8 words are the original key */
    for (i = 0; i < NK; i++)
    {
        round_keys[i] = ((uint32_t)key[4*i] << 24) |
                        ((uint32_t)key[4*i+1] << 16) |
                        ((uint32_t)key[4*i+2] << 8) |
                        ((uint32_t)key[4*i+3]);
    }

    /* Generate remaining words */
    for (i = NK; i < KEY_EXP_SIZE; i++)
    {
        temp = round_keys[i - 1];

        if ((i % NK) == 0)
        {
            /* RotWord + SubWord + Rcon */
            temp = ((uint32_t)g_sbox[(temp >> 16) & 0xFF] << 24) |
                   ((uint32_t)g_sbox[(temp >> 8) & 0xFF] << 16) |
                   ((uint32_t)g_sbox[temp & 0xFF] << 8) |
                   ((uint32_t)g_sbox[(temp >> 24) & 0xFF]);
            temp ^= ((uint32_t)g_rcon[i / NK] << 24);
        }
        else if ((i % NK) == 4)
        {
            /* SubWord only (AES-256 specific) */
            temp = ((uint32_t)g_sbox[(temp >> 24) & 0xFF] << 24) |
                   ((uint32_t)g_sbox[(temp >> 16) & 0xFF] << 16) |
                   ((uint32_t)g_sbox[(temp >> 8) & 0xFF] << 8) |
                   ((uint32_t)g_sbox[temp & 0xFF]);
        }

        round_keys[i] = round_keys[i - NK] ^ temp;
    }
}


/*============================================================================*/
/* AES Decryption Primitives                                                  */
/*============================================================================*/

/**
 * @brief Add round key to state (XOR)
 */
static void
add_round_key                  (uint8_t*                state,
                                const uint32_t*         round_key)
{
    int                         i;

    for (i = 0; i < 4; i++)
    {
        state[4*i]   ^= (uint8_t)(round_key[i] >> 24);
        state[4*i+1] ^= (uint8_t)(round_key[i] >> 16);
        state[4*i+2] ^= (uint8_t)(round_key[i] >> 8);
        state[4*i+3] ^= (uint8_t)(round_key[i]);
    }
}


/**
 * @brief Inverse SubBytes transformation
 */
static void
inv_sub_bytes                  (uint8_t*                state)
{
    int                         i;

    for (i = 0; i < 16; i++)
    {
        state[i] = g_inv_sbox[state[i]];
    }
}


/**
 * @brief Inverse ShiftRows transformation
 *
 * State is column-major:
 *   [ 0  4  8 12 ]      [ 0  4  8 12 ]
 *   [ 1  5  9 13 ]  ->  [ 13 1  5  9 ]
 *   [ 2  6 10 14 ]      [ 10 14 2  6 ]
 *   [ 3  7 11 15 ]      [ 7  11 15 3 ]
 */
static void
inv_shift_rows                 (uint8_t*                state)
{
    uint8_t                     temp;

    /* Row 1: shift right by 1 */
    temp      = state[13];
    state[13] = state[9];
    state[9]  = state[5];
    state[5]  = state[1];
    state[1]  = temp;

    /* Row 2: shift right by 2 */
    temp      = state[2];
    state[2]  = state[10];
    state[10] = temp;
    temp      = state[6];
    state[6]  = state[14];
    state[14] = temp;

    /* Row 3: shift right by 3 (= shift left by 1) */
    temp      = state[3];
    state[3]  = state[7];
    state[7]  = state[11];
    state[11] = state[15];
    state[15] = temp;
}


/**
 * @brief Inverse MixColumns transformation
 *
 * Multiply each column by inverse matrix:
 *   [0E 0B 0D 09]
 *   [09 0E 0B 0D]
 *   [0D 09 0E 0B]
 *   [0B 0D 09 0E]
 */
static void
inv_mix_columns                (uint8_t*                state)
{
    uint8_t                     a, b, c, d;
    int                         i;

    for (i = 0; i < 4; i++)
    {
        a = state[4*i];
        b = state[4*i+1];
        c = state[4*i+2];
        d = state[4*i+3];

        state[4*i]   = gf_mul(a, 0x0E) ^ gf_mul(b, 0x0B) ^
                       gf_mul(c, 0x0D) ^ gf_mul(d, 0x09);
        state[4*i+1] = gf_mul(a, 0x09) ^ gf_mul(b, 0x0E) ^
                       gf_mul(c, 0x0B) ^ gf_mul(d, 0x0D);
        state[4*i+2] = gf_mul(a, 0x0D) ^ gf_mul(b, 0x09) ^
                       gf_mul(c, 0x0E) ^ gf_mul(d, 0x0B);
        state[4*i+3] = gf_mul(a, 0x0B) ^ gf_mul(b, 0x0D) ^
                       gf_mul(c, 0x09) ^ gf_mul(d, 0x0E);
    }
}


/*============================================================================*/
/* AES Block Decryption                                                       */
/*============================================================================*/

/**
 * @brief Decrypt single AES block
 *
 * @param[out] plaintext   Output plaintext (16 bytes)
 * @param[in]  ciphertext  Input ciphertext (16 bytes)
 * @param[in]  round_keys  Expanded round keys
 */
static void
aes_decrypt_block              (uint8_t*                plaintext,
                                const uint8_t*          ciphertext,
                                const uint32_t*         round_keys)
{
    uint8_t                     state[16];
    int                         round;

    /* Copy ciphertext to state */
    memcpy(state, ciphertext, 16);

    /* Initial round key addition (round NR) */
    add_round_key(state, &round_keys[NR * NB]);

    /* Main rounds (NR-1 down to 1) */
    for (round = NR - 1; round > 0; round--)
    {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, &round_keys[round * NB]);
        inv_mix_columns(state);
    }

    /* Final round (no InvMixColumns) */
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, &round_keys[0]);

    /* Copy state to plaintext */
    memcpy(plaintext, state, 16);
}


/*============================================================================*/
/* Public API                                                                 */
/*============================================================================*/

int
aes256_cbc_decrypt             (const uint8_t*          p_key,
                                const uint8_t*          p_iv,
                                const uint8_t*          p_ciphertext,
                                size_t                  len,
                                uint8_t*                p_plaintext)
{
    uint32_t                    round_keys[KEY_EXP_SIZE];
    uint8_t                     prev_block[AES256_BLOCK_SIZE];
    uint8_t                     curr_block[AES256_BLOCK_SIZE];
    size_t                      num_blocks;
    size_t                      i, j;

    /* Parameter validation */
    if ((p_key == NULL) || (p_iv == NULL) ||
        (p_ciphertext == NULL) || (p_plaintext == NULL))
    {
        return AES256_ERR_PARAM;
    }

    /* Length must be multiple of block size */
    if ((len == 0) || ((len % AES256_BLOCK_SIZE) != 0))
    {
        return AES256_ERR_LENGTH;
    }

    /* Expand key */
    key_expansion(round_keys, p_key);

    /* Initialize previous block with IV */
    memcpy(prev_block, p_iv, AES256_BLOCK_SIZE);

    /* Process each block */
    num_blocks = len / AES256_BLOCK_SIZE;

    for (i = 0; i < num_blocks; i++)
    {
        /* Save current ciphertext block (needed for XOR with next block) */
        memcpy(curr_block, &p_ciphertext[i * AES256_BLOCK_SIZE], AES256_BLOCK_SIZE);

        /* Decrypt block */
        aes_decrypt_block(&p_plaintext[i * AES256_BLOCK_SIZE],
                          curr_block,
                          round_keys);

        /* XOR with previous ciphertext (or IV for first block) */
        for (j = 0; j < AES256_BLOCK_SIZE; j++)
        {
            p_plaintext[i * AES256_BLOCK_SIZE + j] ^= prev_block[j];
        }

        /* Update previous block for next iteration */
        memcpy(prev_block, curr_block, AES256_BLOCK_SIZE);
    }

    /* Clear sensitive data from stack */
    secure_memzero(round_keys, sizeof(round_keys));
    secure_memzero(prev_block, sizeof(prev_block));
    secure_memzero(curr_block, sizeof(curr_block));

    return AES256_OK;
}
