/*
 * SPDX-FileCopyrightText: 2026 TU Dresden
 * SPDX-License-Identifier: LGPL-2.1-only
 */
/**
 * @ingroup     sys_psa_crypto
 * @defgroup    sys_psa_crypto_rsa  PSA Wrapper Functions: RSA
 * @{
 *
 * @file        psa_rsa.h
 * @brief       Function declarations for low level wrapper functions for RSA operations.
 *
 * @author      Lukas Luger <lukas.luger@mailbox.tu-dresden.de>
 */
#include "psa/crypto.h"
#include "relic.h"
#include <stdio.h>

#define HASH_SIZE PSA_HASH_LENGTH(PSA_ALG_SHA_384)

uint16_t parse_der_length(const uint8_t *data)
{
    uint16_t ret;
    if (data[0] & 0x80) {
        // more than one byte for length needed
        if ((data[0] & 0x7f) > 2) {
            // we do not support lengths above 2 Bytes aka 65.536 Bytes
            ret = 0xffff;            
        }
        else if ((data[0] & 0x7f) == 1) {
            ret = data[1];
        }
        else {
            ret = data[1] << 8 | data[2];
        }
    }
    else {
        ret = data[0];
    }
    return ret;
}

uint8_t get_der_length_offset(const uint8_t *data)
{
    uint8_t ret = 0;
    if (data[0] & 0x80) {
        ret++;
        if ((data[0] & 0x7f) > 2) {
            // we do not support lengths above 2 Bytes aka 65.536 Bytes
            ret = 0xff;            
        }
        else {
            ret += data[0] & 0x7f;
        }
    }
    else {
        ret++;
    }
    return ret;
}

psa_status_t parse_pub_key(const uint8_t *data, size_t data_len, bn_t n, bn_t e)
{
    uint16_t index = 0; 
    uint16_t tmp_size;
    // verify preamble (should start as sequence)
    if (data_len == 0 || data[0] != 0x30) {
        return PSA_ERROR_DATA_INVALID;
    }
    index++;
    tmp_size = parse_der_length(&data[index]);
    if (tmp_size == 0xffff || tmp_size > data_len) {
        return PSA_ERROR_DATA_INVALID;
    }

    index += get_der_length_offset(&data[index]);
    // verify version
    if (!(data[index] == 0x02 /* int */ && data[index+1] == 0x02 /* 2 bytes */ && \
        data[index+2] == 0x00 /* leading byte */&& data[index+3] == 0x00 /* value */)) {
            return PSA_ERROR_DATA_INVALID;
    }
    index += 4;
    
    // import n
    if (data[index] != 0x02) {
        // following data is not int
        return PSA_ERROR_DATA_INVALID;
    }
    index++;
    /* remove one byte because of useless zero leading byte */
    tmp_size = parse_der_length(&data[index]) - 1;
    index += get_der_length_offset(&data[index]) + 1;
    bn_read_bin(n, &data[index], tmp_size);
    index += tmp_size;

    // import e
    if (data[index] != 0x02) {
        // following data is not int
        return PSA_ERROR_DATA_INVALID;
    }
    index++;
    /* remove one byte because of useless zero leading byte */
    tmp_size = parse_der_length(&data[index]) - 1;
    index += get_der_length_offset(&data[index]) + 1;
    bn_read_bin(e, &data[index], tmp_size);
    return PSA_SUCCESS;
}

psa_status_t psa_derive_rsa_public_key( const uint8_t *priv_key_buffer, size_t privkey_buffer_lenghth,
                                        uint8_t *pub_key_buffer, size_t *pub_key_buffer_length)
{
    // pub key is subset of privkey
    uint16_t size = 0;
    uint16_t tmp_size;
    if (privkey_buffer_lenghth == 0 || priv_key_buffer[0] != 0x30) {
        return PSA_ERROR_DATA_INVALID;
    }
    size++;
    tmp_size = parse_der_length(&priv_key_buffer[size]);
    if (tmp_size == 0xffff || tmp_size > privkey_buffer_lenghth) {
        return PSA_ERROR_DATA_INVALID;
    }

    size += get_der_length_offset(&priv_key_buffer[size]);
    // verify version
    if (!(priv_key_buffer[size] == 0x02 /* int */ && priv_key_buffer[size+1] == 0x02 /* 2 bytes */ && \
        priv_key_buffer[size+2] == 0x00 /* leading byte */&& priv_key_buffer[size+3] == 0x00 /* value */)) {
            return PSA_ERROR_DATA_INVALID;
    }
    size += 4;
    // n
    if (priv_key_buffer[size] != 0x02) {
        // following data is not int
        return PSA_ERROR_DATA_INVALID;
    }
    size++;
    tmp_size = parse_der_length(&priv_key_buffer[size]);
    size += get_der_length_offset(&priv_key_buffer[size]) + tmp_size;
    // e
    if (priv_key_buffer[size] != 0x02) {
        // following data is not int
        return PSA_ERROR_DATA_INVALID;
    }
    size++;
    tmp_size = parse_der_length(&priv_key_buffer[size]);
    size += get_der_length_offset(&priv_key_buffer[size]) + tmp_size;

    *pub_key_buffer_length = size;
    memcpy(pub_key_buffer, priv_key_buffer, size);
    if (pub_key_buffer[1] == 0x82) {
        /* length indication is 2 bytes */
        tmp_size = size - 4;
        pub_key_buffer[2] = (tmp_size >> 8) & 0xff;
        pub_key_buffer[3] = tmp_size & 0xff;
    }

    return PSA_SUCCESS;
}

psa_status_t rsassa_pss_verify(bn_t n, bn_t e, const uint8_t *msg, size_t msg_length, const uint8_t *sig, size_t sig_length)
{
    if (sig_length != bn_size_bin(n)) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }
    bn_t m, s;
    
    bn_null(m);
    bn_null(s);

    bn_new(m);
    bn_null(s);

    bn_read_bin(s, sig, sig_length);

    /* m ?= RSAVP1((n,e), s) */
    bn_mxp(m, s, e, n);
    size_t size = bn_size_bin(n);
    uint8_t tmp_msg[size];

    if (size <= sig_length) {
        memset(tmp_msg, 0, size);
        bn_write_bin(tmp_msg, size, s);
        if (!(memcmp(tmp_msg, msg, size) && size == msg_length)) {
            return PSA_ERROR_INVALID_SIGNATURE;
        }
    }
    else {
        return PSA_ERROR_BAD_STATE;
    }
    /* verify encoded message, but this is redundant in our case */
    //emsa_pss_verify()    
    return PSA_SUCCESS;
}

psa_status_t psa_bs_rsa_verify_message(const uint8_t *pubkey_data, size_t pubkey_data_len, const uint8_t *input,
                                     size_t input_length, const uint8_t *signature, size_t signature_length)
{
    bn_t s, m, n, e;
    bn_null(s);
    bn_null(m);
    bn_null(n);
    bn_null(e);

    bn_new(s);
    bn_new(m);
    bn_new(n);
    bn_new(e);

    psa_status_t status = parse_pub_key(pubkey_data, pubkey_data_len, n, e);
    if (status != PSA_SUCCESS) {
        return status;
    }
    return rsassa_pss_verify(n, e, input, input_length, signature, signature_length);
}

psa_status_t psa_bs_rsa_sign_message(  const psa_key_attributes_t *attributes, psa_algorithm_t alg, uint8_t *key_data,
                                    size_t key_bytes, const uint8_t *input, size_t input_length, uint8_t *signature,
                                    size_t signature_size, size_t *signature_length)
{
    (void)attributes;
    (void)alg;
    bn_t n, d;
    bn_null(n);
    bn_null(d);
    bn_new(n);
    bn_new(d);
    /* READING DER PRIVATE KEY */
    /* hopefully always less than 65.536 Bytes */
    uint16_t index = 0; 
    uint16_t tmp_size;
    // verify preamble (should start as sequence)
    if (key_bytes == 0 || key_data[0] != 0x30) {
        return PSA_ERROR_DATA_INVALID;
    }
    index++;
    tmp_size = parse_der_length(&key_data[index]);
    if (tmp_size == 0xffff || tmp_size > key_bytes) {
        return PSA_ERROR_DATA_INVALID;
    }

    index += get_der_length_offset(&key_data[index]);
    // verify version
    if (!(key_data[index] == 0x02 /* int */ && key_data[index+1] == 0x02 /* 2 bytes */ && \
        key_data[index+2] == 0x00 /* leading byte */&& key_data[index+3] == 0x00 /* value */)) {
            return PSA_ERROR_DATA_INVALID;
    }
    index += 4;
    
    // import n
    if (key_data[index] != 0x02) {
        // following data is not int
        return PSA_ERROR_DATA_INVALID;
    }
    index++;
    /* remove one byte because of useless zero leading byte */
    tmp_size = parse_der_length(&key_data[index]) - 1;
    index += get_der_length_offset(&key_data[index]) + 1;

    bn_read_bin(n, &key_data[index], tmp_size);
    index += tmp_size;
    
    // skip e
    if (key_data[index] != 0x02) {
        // following data is not int
        return PSA_ERROR_DATA_INVALID;
    }
    index++;
    tmp_size = parse_der_length(&key_data[index]);
    index += get_der_length_offset(&key_data[index]) + tmp_size;

    // import d
    if (key_data[index] != 0x02) {
        // following data is not int
        return PSA_ERROR_DATA_INVALID;
    }
    index++;
    /* remove one byte because of useless zero leading byte */
    tmp_size = parse_der_length(&key_data[index]) - 1;
    index += get_der_length_offset(&key_data[index]) + 1;
    bn_read_bin(d, &key_data[index], tmp_size);
    index += tmp_size;

    // ignore primes and other params
    bn_t s, m;
    bn_null(s);
    bn_null(m);
    bn_new(s);
    bn_new(m);
    bn_read_bin(m, input, input_length);
    bn_mxp(s, m, d, n);
    size_t size = bn_size_bin(n);
    if (size <= signature_size) {
        memset(signature, 0, size);
        bn_write_bin(signature, size, s);
        *signature_length = size;
        return PSA_SUCCESS;
    }
    return PSA_ERROR_BAD_STATE;
}

psa_status_t mgf_one(uint8_t *mgfSeed, size_t maskLen, uint8_t *mask)
{
    /* calculate ceil(maskLen/hLen) */
    uint32_t cmax = 0;
    uint32_t counter = maskLen;
    do {
        if (counter > HASH_SIZE) {
            counter -= HASH_SIZE;
        }
        else {
            counter = 0;
        }
        cmax++;
    } while(counter != 0);
    /* generate empty octet string T */
    uint8_t T[cmax*HASH_SIZE];
    uint8_t tmp[HASH_SIZE+4];
    psa_status_t status = PSA_ERROR_BAD_STATE;
    size_t len;
    for (counter = 0; counter < cmax; counter++) {
        /* T = T || Hash(mgfSeed || C)*/
        memcpy(tmp, mgfSeed, HASH_SIZE);
        tmp[HASH_SIZE] = (counter >> 24) & 0xff;
        tmp[HASH_SIZE+1] = (counter >> 16) & 0xff;
        tmp[HASH_SIZE+2] = (counter >> 8) & 0xff;
        tmp[HASH_SIZE+3] = counter & 0xff;

        status = psa_hash_compute(PSA_ALG_SHA_384, tmp, sizeof(tmp),
                              &T[(counter)*HASH_SIZE],
                              HASH_SIZE, &len);
        if (status != PSA_SUCCESS || len != HASH_SIZE) {
            return status;
        }
    }
    /* output leading maskLen bytes */
    memcpy(mask, T, maskLen);
    return PSA_SUCCESS;

}

psa_status_t emsa_pss_encode_zero_salt(const uint8_t *M, size_t msize, uint8_t *EM, uint32_t emBits)
{
    /* calculate emLen */
    uint32_t counter = emBits;
    size_t emLen = 0;
    do {
        if (counter > 8) {
            counter -= 8;
        }
        else {
            counter = 0;
        }
        emLen++;
    } while(counter != 0);

    if ( emLen < HASH_SIZE + 2) {
        return PSA_ERROR_DATA_INVALID;
    }
    uint8_t hash1[HASH_SIZE];
    uint8_t hash2[HASH_SIZE + 8];
    size_t tmp_len;
    /* compute mHash = Hash(M) */
    psa_hash_compute(PSA_ALG_SHA_384, M, msize, hash1, sizeof(hash1), &tmp_len);
    /* generate M' = 00 00 00 00 00 00 00 00 || mHash */
    memset(hash2, 0, sizeof(hash2));
    memcpy(&hash2[8], hash1, sizeof(hash1));
    /* compute H = Hash(M) (reusing hash1 as H)*/
    memset(hash1, 0, sizeof(hash1));
    psa_hash_compute(PSA_ALG_SHA_384, hash2, sizeof(hash2), hash1, sizeof(hash1), &tmp_len);
    /* generate DB = 00 ... 00 || 0x01 */
    size_t dbLen = emLen - HASH_SIZE -1;
    uint8_t DB[dbLen];
    memset(DB, 0, sizeof(DB));
    DB[dbLen - 1] = 0x01;
    /* dbMask = MGF1(H, dbLen)*/
    uint8_t dbMask[dbLen];
    psa_status_t status = mgf_one(hash1, dbLen, dbMask);
    if (status != PSA_SUCCESS) {
        return status;
    }
    /* maskedDB = DB xor dbMask */
    for (counter = 0; counter < dbLen; counter++) {
        dbMask[counter] ^= DB[counter];
    }
    memcpy(EM, dbMask, sizeof(dbMask));
    memcpy(&EM[sizeof(dbMask)], hash1, sizeof(hash1));
    EM[sizeof(dbMask) + sizeof(hash1)] = 0xbc;
    return PSA_SUCCESS;

}

// psa_status_t emsa_pss_verify(uint8_t *M, size_t mSize, uint8_t *EM, uint32_t emBits)
// {
//     if (mSize > HASH_SIZE) {
//         return PSA_ERROR_BAD_STATE;
//     }
//     /* compute emLen */
//     uint32_t counter = emBits;
//     size_t emLen = 0;
//     do {
//         if (counter > 8) {
//             counter -= 8;
//         }
//         else {
//             counter = 0;
//         }
//         emLen++;
//     } while(counter != 0);

//     if (emLen < HASH_SIZE + 2 || EM[emLen-1] != 0xbc) {
//         return PSA_ERROR_BAD_STATE;
//     }
//     size_t tmp_len;
//     uint8_t hash1[HASH_SIZE];
//     psa_hash_compute(PSA_ALG_SHA_384, M, mSize, hash1, sizeof(hash1), &tmp_len);

//     puts("EM");
//     od_hex_dump(EM, emLen, 16);

//     size_t mask_len = emLen - HASH_SIZE - 1;
//     // uint8_t maskedDB[mask_len];
//     // memcpy(maskedDB, EM, mask_len);
//     // puts("maskedDB");
//     // od_hex_dump(maskedDB, mask_len, 16);

//     uint8_t H[HASH_SIZE];
//     memcpy(H, &EM[mask_len], HASH_SIZE);
//     puts("H");
//     od_hex_dump(H, sizeof(H), 16);

//     // uint8_t DB[mask_len];
//     // mgf_one(H, mask_len, DB);
//     // for (counter = 1; counter < mask_len; counter++) {
//     //     DB[counter] ^= maskedDB[counter];
//     // }

//     uint8_t hash2[HASH_SIZE+8];
//     memset(hash2, 0, sizeof(hash2));
//     memcpy(&hash2[8], hash1, sizeof(hash1));
//     psa_hash_compute(PSA_ALG_SHA_384, hash2, sizeof(hash2), hash1, sizeof(hash1), &tmp_len);

//     if (memcmp(hash1, H, HASH_SIZE) == 0) {
//         return PSA_SUCCESS;
//     }
//     return PSA_ERROR_INVALID_SIGNATURE;
// }



psa_status_t psa_bs_rsa_blind_message(  const uint8_t *pubkey_data, size_t pubkey_data_len,
                                        const uint8_t *input, size_t input_length,
                                        const uint8_t *prandom, size_t prandom_length,
                                        uint8_t *inverse, size_t inverse_length,
                                        const uint8_t *output, size_t output_size, size_t *output_length)
{
    bn_t x, r, m, n, e, inv;
    bn_null(x);
    bn_null(r);
    bn_null(m);
    bn_null(n);
    bn_null(e);
    bn_null(inv);

    bn_new(x);
    bn_new(r);
    bn_new(m);
    bn_new(n);
    bn_new(e);
    bn_new(inv);

    psa_status_t status = parse_pub_key(pubkey_data, pubkey_data_len, n, e);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (output_size < bn_size_bin(n)) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    uint8_t enc_msg[bn_size_bin(n)];
    emsa_pss_encode_zero_salt(input, input_length, enc_msg, bn_size_bin(n)*8);
    bn_read_bin(m, enc_msg, sizeof(enc_msg));

    bn_read_bin(r, prandom, prandom_length);
    if (RLC_LT != bn_cmp(r, n)) {
        return PSA_ERROR_DATA_INVALID;
    }
    
    /* save inverse */
    bn_mod_inv(inv, r, n);
    bn_write_bin(inverse, inverse_length, inv);   
    
    /* x = RSAVP1(pk, r) = r^e mod n */
    bn_mxp(x, r, e, n);
    
    /* m = m*x mod n */
    bn_mul(m, m, x);
    bn_mod(m, m, n);
    
    bn_write_bin((uint8_t *)output, bn_size_bin(m), m);
    *output_length = bn_size_bin(m);

    return PSA_SUCCESS;
}

psa_status_t psa_bs_rsa_unblind_signature(  const uint8_t *pubkey_data, size_t pubkey_data_len,
                                            const uint8_t *input, size_t input_length,
                                            uint8_t *inverse, size_t inverse_length,
                                            const uint8_t *output, size_t output_size, size_t *output_length)
{
    bn_t bs, s, n, e, inv;
    bn_null(bs);
    bn_null(s);
    bn_null(n);
    bn_null(e);
    bn_null(inv);

    bn_new(bs);
    bn_new(s);
    bn_new(n);
    bn_new(e);
    bn_new(inv);

    psa_status_t status = parse_pub_key(pubkey_data, pubkey_data_len, n, e);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (output_size < bn_size_bin(n)) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    if (input_length != bn_size_bin(n)) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }
    
    bn_read_bin(bs, input, input_length);
    bn_read_bin(inv, inverse, inverse_length);
    
    /* s = bs * inv mod n */
    bn_mul(s, bs, inv);
    bn_mod(s, s, n);

    bn_write_bin((uint8_t *)output, bn_size_bin(s), s);
    *output_length = bn_size_bin(s);
    
    return PSA_SUCCESS;
}