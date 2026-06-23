/*
 * SPDX-FileCopyrightText: 2026 TU Dresden
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include "relic.h"
#include <stdio.h>
#include "hashes/sha384.h"

#define HASH_SIZE SHA384_DIGEST_LENGTH

uint8_t emsa_pss_verify(bn_t m, bn_t em, uint32_t emBits)
{
    if (bn_size_bin(m) > HASH_SIZE) {
        return -1;
    }
    /* compute emLen */
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

    uint8_t EM[512];
    bn_write_bin(EM, sizeof(EM), em);
    if (emLen < HASH_SIZE + 2 || EM[emLen-1] != 0xbc) {
        return -1;
    }

    uint8_t hash1[HASH_SIZE];
    uint8_t M[bn_size_bin(m)];
    bn_write_bin(M, sizeof(M), m);
    sha384(M, sizeof(M), hash1);

    size_t mask_len = emLen - HASH_SIZE - 1;
    // uint8_t maskedDB[mask_len];
    // memcpy(maskedDB, EM, mask_len);

    uint8_t H[HASH_SIZE];
    memcpy(H, &EM[mask_len], HASH_SIZE);

    // uint8_t DB[mask_len];
    // mgf_one(H, mask_len, DB);
    // for (counter = 1; counter < mask_len; counter++) {
    //     DB[counter] ^= maskedDB[counter];
    // }

    uint8_t hash2[HASH_SIZE+8];
    memset(hash2, 0, sizeof(hash2));
    memcpy(&hash2[8], hash1, sizeof(hash1));
    sha384(hash2, sizeof(hash2), hash1);

    if (memcmp(hash1, H, HASH_SIZE) == 0) {
        return 0;
    }
    return -1;
}

uint8_t rsassa_pss_verify(bn_t n, bn_t e, const uint8_t *msg, size_t msg_length, const uint8_t *sig, size_t sig_length)
{
    if (sig_length != bn_size_bin(n)) {
        return -1;
    }
    bn_t m, s;
    
    bn_null(m);
    bn_null(s);

    bn_new(m);
    bn_new(s);

    bn_read_bin(m, msg, msg_length);

    bn_read_bin(s, sig, sig_length);

    /* EMSA_PSS(m) ?= RSAVP1((n,e), s) */
    bn_mxp(s, s, e, n);

    /* verify encoded message, but this is redundant in our case */
    uint8_t status = emsa_pss_verify(m, s, (bn_size_bin(n)*8)-1);
    bn_free(m);
    bn_free(s);
    return status;
}

uint8_t bs_rsa_verify_message(const uint8_t *nin, size_t nlen, const uint8_t *ein, size_t elen, const uint8_t *input,
                                     size_t input_length, const uint8_t *signature, size_t signature_length)
{
    bn_t n, e;
    bn_null(n);
    bn_null(e);

    bn_new(n);
    bn_new(e);

    bn_read_bin(n, nin, nlen);
    bn_read_bin(e, ein, elen);
    uint8_t status = rsassa_pss_verify(n, e, input, input_length, signature, signature_length);
    bn_free(n);
    bn_free(e);
    return status;
}

uint8_t bs_rsa_fdh_verify_hash(const uint8_t *nin, size_t nlen, const uint8_t *ein, size_t elen, const uint8_t *input,
                                     size_t input_length, const uint8_t *signature, size_t signature_length)
{
    bn_t n, e, m, s;
    bn_null(n);
    bn_null(e);
    bn_null(m);
    bn_null(s);

    bn_new(n);
    bn_new(e);
    bn_new(m);
    bn_new(s);

    bn_read_bin(n, nin, nlen);
    bn_read_bin(e, ein, elen);
    bn_read_bin(m, input, input_length);
    bn_read_bin(s, signature, signature_length);

    bn_mxp(s, s, e, n);

    uint8_t status = (bn_cmp(m,s) == RLC_EQ) ? 0 : -1;

    bn_free(n);
    bn_free(e);
    bn_free(m);
    bn_free(s);

    return status;
}

uint8_t bs_rsa_sign_message(  const uint8_t *nin, size_t nlen, const uint8_t *din, size_t dlen, const uint8_t *input,
                                size_t input_length, uint8_t *signature,
                                    size_t signature_size, size_t *signature_length)
{
    bn_t n, d, s, m;
    bn_null(n);
    bn_null(d);
    bn_null(s);
    bn_null(m);

    bn_new(n);
    bn_new(d);
    bn_new(s);
    bn_new(m);

    bn_read_bin(n, nin, nlen);
    bn_read_bin(d, din, dlen);

    bn_read_bin(m, input, input_length);
    bn_mxp(s, m, d, n);
    size_t size = bn_size_bin(n);
    uint8_t status;
    if (size <= signature_size) {
        memset(signature, 0, size);
        bn_write_bin(signature, size, s);
        *signature_length = size;
        status = 0;
    }
    else {
        status = -1;
    }
    bn_free(n);
    bn_free(d);
    bn_free(s);
    bn_free(m);
    return status;
}

uint8_t bs_rsa_fdh_sign_hash(   const uint8_t *nin, size_t nlen, const uint8_t *din, size_t dlen,
                        const uint8_t *input, size_t input_length, uint8_t *signature,
                                    size_t signature_size, size_t *signature_length)
{
    return bs_rsa_sign_message( nin, nlen, din, dlen, input, input_length, signature,
                                    signature_size, signature_length);
}

uint8_t mgf_one(uint8_t *mgfSeed, size_t maskLen, uint8_t *mask)
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
    for (counter = 0; counter < cmax; counter++) {
        /* T = T || Hash(mgfSeed || C)*/
        memcpy(tmp, mgfSeed, HASH_SIZE);
        tmp[HASH_SIZE] = (counter >> 24) & 0xff;
        tmp[HASH_SIZE+1] = (counter >> 16) & 0xff;
        tmp[HASH_SIZE+2] = (counter >> 8) & 0xff;
        tmp[HASH_SIZE+3] = counter & 0xff;

        sha384(tmp, sizeof(tmp),
                              &T[(counter)*HASH_SIZE]);
    }
    /* output leading maskLen bytes */
    memcpy(mask, T, maskLen);
    return 0;

}

uint8_t emsa_pss_encode_zero_salt(const uint8_t *M, size_t msize, uint8_t *EM, uint32_t emBits)
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
        return -1;
    }
    uint8_t hash1[HASH_SIZE];
    uint8_t hash2[HASH_SIZE + 8];
    /* compute mHash = Hash(M) */
    sha384(M, msize, hash1);
    /* generate M' = 00 00 00 00 00 00 00 00 || mHash */
    memset(hash2, 0, sizeof(hash2));
    memcpy(&hash2[8], hash1, sizeof(hash1));
    /* compute H = Hash(M) (reusing hash1 as H)*/
    memset(hash1, 0, sizeof(hash1));
    sha384(hash2, sizeof(hash2), hash1);
    /* generate DB = 00 ... 00 || 0x01 */
    size_t dbLen = emLen - HASH_SIZE -1;
    uint8_t DB[dbLen];
    memset(DB, 0, sizeof(DB));
    DB[dbLen - 1] = 0x01;
    /* dbMask = MGF1(H, dbLen)*/
    uint8_t dbMask[dbLen];
    uint8_t status = mgf_one(hash1, dbLen, dbMask);
    if (status != 0) {
        return -1;
    }
    /* maskedDB = DB xor dbMask */
    for (counter = 0; counter < dbLen; counter++) {
        dbMask[counter] ^= DB[counter];
    }
    memcpy(EM, dbMask, sizeof(dbMask));
    memcpy(&EM[sizeof(dbMask)], hash1, sizeof(hash1));
    EM[sizeof(dbMask) + sizeof(hash1)] = 0xbc;
    return 0;

}




uint8_t bs_rsa_blind_message(  const uint8_t *nin, size_t nlen, const uint8_t *ein, size_t elen,
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

    bn_read_bin(n, nin, nlen);
    bn_read_bin(e, ein, elen);
    

    if (output_size < bn_size_bin(n)) {
        return -1;
    }

    uint8_t enc_msg[bn_size_bin(n)];
    emsa_pss_encode_zero_salt(input, input_length, enc_msg, bn_size_bin(n)*8);
    bn_read_bin(m, enc_msg, sizeof(enc_msg));

    bn_read_bin(r, prandom, prandom_length);
    if (RLC_LT != bn_cmp(r, n)) {
        return -1;
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

    bn_free(x);
    bn_free(r);
    bn_free(m);
    bn_free(n);
    bn_free(e);
    bn_free(inv);
    return 0;
}

uint8_t bs_rsa_fdh_blind_hash( const uint8_t *nin, size_t nlen, const uint8_t *ein, size_t elen,
                                        const uint8_t *input, size_t input_length,
                                        const uint8_t *prandom, size_t prandom_length,
                                        uint8_t *inverse, size_t inverse_length,
                                        const uint8_t *output, size_t output_size, size_t *output_length)
{
    bn_t r, m, n, e, inv;
    bn_null(r);
    bn_null(m);
    bn_null(n);
    bn_null(e);
    bn_null(inv);

    bn_new(r);
    bn_new(m);
    bn_new(n);
    bn_new(e);
    bn_new(inv);

    bn_read_bin(n, nin, nlen);
    bn_read_bin(e, ein, elen);

    if (output_size < bn_size_bin(n)) {
        return -1;
    }

    bn_read_bin(m, input, input_length);

    bn_read_bin(r, prandom, prandom_length);

    /* save the fdh derived 'inverse' */
    bn_mod_inv(inv, r, n);
    bn_write_bin(inverse, inverse_length, inv);   

    /* x = RSAVP1(pk, r) = r^e mod n */
    bn_mxp(r, r, e, n);

    /* m = m*x mod n */
    bn_mul(r, r, m);
    bn_mod(r, r, n);

    bn_write_bin((uint8_t *)output, bn_size_bin(r), r);
    *output_length = bn_size_bin(r);

    bn_free(r);
    bn_free(m);
    bn_free(n);
    bn_free(e);
    bn_free(inv);
    return 0;
}

uint8_t bs_rsa_unblind_signature(  const uint8_t *nin, size_t nlen, const uint8_t *ein, size_t elen,
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


    bn_read_bin(n, nin, nlen);
    bn_read_bin(e, ein, elen);

    if (output_size < bn_size_bin(n)) {
        return -1;
    }

    if (input_length != bn_size_bin(n)) {
        return -1;
    }
    
    bn_read_bin(bs, input, input_length);
    bn_read_bin(inv, inverse, inverse_length);
    
    /* s = bs * inv mod n */
    bn_mul(s, bs, inv);
    bn_mod(s, s, n);

    bn_write_bin((uint8_t *)output, bn_size_bin(s), s);
    *output_length = bn_size_bin(s);
    
    bn_free(bs);
    bn_free(s);
    bn_free(n);
    bn_free(e);
    bn_free(inv);
    return 0;
}

uint8_t bs_rsa_fdh_unblind_signature(  const uint8_t *nin, size_t nlen, const uint8_t *ein, size_t elen,
                                            const uint8_t *input, size_t input_length,
                                            uint8_t *inverse, size_t inverse_length,
                                            const uint8_t *output, size_t output_size, size_t *output_length)
{
    return bs_rsa_unblind_signature(nin, nlen, ein, elen, input, input_length, inverse, inverse_length,
                                        output, output_size, output_length);
}