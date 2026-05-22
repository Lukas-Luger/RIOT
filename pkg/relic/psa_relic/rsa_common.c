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

psa_status_t parse_priv_key(const uint8_t *data, size_t data_len, bn_t n, bn_t d)
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
    
    // skip e
    if (data[index] != 0x02) {
        // following data is not int
        return PSA_ERROR_DATA_INVALID;
    }
    index++;
    tmp_size = parse_der_length(&data[index]);
    index += get_der_length_offset(&data[index]) + tmp_size;

    // import d
    if (data[index] != 0x02) {
        // following data is not int
        return PSA_ERROR_DATA_INVALID;
    }
    index++;
    /* remove one byte because of useless zero leading byte */
    tmp_size = parse_der_length(&data[index]) - 1;
    index += get_der_length_offset(&data[index]) + 1;
    bn_read_bin(d, &data[index], tmp_size);
    index += tmp_size;
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