/*
 * SPDX-FileCopyrightText: 2026 TU Dresden
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#pragma once

/**
 * @ingroup     sys_psa_crypto
 * @defgroup    sys_psa_crypto_bs  PSA Wrapper Functions: Blind signaturees
 * @{
 *
 * @file        psa_bs.h
 * @brief       Function declarations for low level wrapper functions for blind signature operations.
 *
 * @author      Lukas Luger <lukas.luger@mailbox.tu-dresden.de>
 */

#ifdef __cplusplus
extern "C" {
#endif

#include "psa/crypto.h"
#include "kernel_defines.h"

/**
 * @brief   Low level wrapper function to call a driver for deriving an P256R1 public key from the private key.
 */
psa_status_t psa_derive_rsa_public_key( const uint8_t *priv_key_buffer, size_t privkey_buffer_lenghth,
                                        uint8_t *pub_key_buffer, size_t *pub_key_buffer_length);

/**
 * @brief Low level wrapper function to call a driver for verify an RSA signed message.
 */
psa_status_t psa_bs_rsa_verify_message( const uint8_t *pubkey_data, size_t pubkey_data_len, const uint8_t *input,
                                        size_t input_length, const uint8_t *signature, size_t signature_length);

/**
 * @brief Low level wrapper function to call a driver for sign a message with RSA.
 */
psa_status_t psa_bs_rsa_sign_message(   const psa_key_attributes_t *attributes, psa_algorithm_t alg, uint8_t *key_data,
                                        size_t key_bytes, const uint8_t *input, size_t input_length, uint8_t *signature,
                                        size_t signature_size, size_t *signature_length);

/**
 * @brief Low level wrapper function to call a driver for blind a message with RSA.
 */
psa_status_t psa_bs_rsa_blind_message(  const uint8_t *pubkey_data, size_t pubkey_data_len,
                                        const uint8_t *input, size_t input_length,
                                        const uint8_t *prandom, size_t prandom_length,
                                        uint8_t *inverse, size_t inverse_length,
                                        const uint8_t *output, size_t output_size, size_t *output_length);

/**
 * @brief Low level wrapper function to call a driver for unblind a signature with RSA.
 */
psa_status_t psa_bs_rsa_unblind_signature(  const uint8_t *pubkey_data, size_t pubkey_data_len,
                                            const uint8_t *input, size_t input_length,
                                            uint8_t *inverse, size_t inverse_length,
                                            const uint8_t *output, size_t output_size, size_t *output_length);

/****** RSA FDH functions ******/
/**
 * @brief Low level wrapper function to call a driver for blind a hash with RSA.
 */
psa_status_t psa_bs_rsa_fdh_blind_hash(  const uint8_t *pubkey_data, size_t pubkey_data_len,
                                        const uint8_t *input, size_t input_length,
                                        const uint8_t *prandom, size_t prandom_length,
                                        uint8_t *inverse, size_t inverse_length,
                                        const uint8_t *output, size_t output_size, size_t *output_length);

/**
 * @brief Low level wrapper function to call a driver for sign a hash with RSA.
 */
psa_status_t psa_bs_rsa_fdh_sign_hash(  const psa_key_attributes_t *attributes, psa_algorithm_t alg, uint8_t *key_data,
                                        size_t key_bytes, const uint8_t *input, size_t input_length, uint8_t *signature,
                                        size_t signature_size, size_t *signature_length);

/**
 * @brief Low level wrapper function to call a driver for verify an RSA signed hash.
 */
psa_status_t psa_bs_rsa_fdh_verify_hash(const uint8_t *pubkey_data, size_t pubkey_data_len, const uint8_t *input,
                                        size_t input_length, const uint8_t *signature, size_t signature_length);

/**
 * @brief Low level wrapper function to call a driver for unblind a signature with RSA.
 */
psa_status_t psa_bs_rsa_fdh_unblind_signature(  const uint8_t *pubkey_data, size_t pubkey_data_len,
                                                const uint8_t *input, size_t input_length,
                                                uint8_t *inverse, size_t inverse_length,
                                                const uint8_t *output, size_t output_size, size_t *output_length);

/****** CBS functions ******/
/**
 * @brief Low level wrapper function to call a driver for generating a commitment with CBS.
 */
psa_status_t psa_bs_cbs_generate_commitment(    uint8_t *r0, uint8_t *r1,
                                                const uint8_t *ouput, size_t output_size, size_t *output_length);

/**
 * @brief Low level wrapper function to call a driver for blind a message with CBS.
 */
psa_status_t psa_bs_cbs_blind_message(  const uint8_t *pubkey_data, size_t pubkey_data_len,
                                        const uint8_t *input, size_t input_length,
                                        const uint8_t *prandom, size_t prandom_length,
                                        uint8_t *R0, uint8_t *R1,
                                        uint8_t *a0, uint8_t *a1,
                                        const uint8_t *output, size_t output_size, size_t *output_length);

/**
 * @brief Low level wrapper function to call a driver for sign a message with CBS.
 */
psa_status_t psa_bs_cbs_sign_message(  const psa_key_attributes_t *attributes, uint8_t *priv_key,
                                        size_t key_bytes, const uint8_t *bmessage, size_t bsize,
                                        uint8_t *r0, uint8_t *r1,
                                        uint8_t *bsignature, size_t bs_size, size_t *bs_length);

/**
 * @brief Low level wrapper function to call a driver for unblinding a signature with CBS.
 */
psa_status_t psa_bs_cbs_unblind_signature(  const uint8_t *input, size_t input_length,
                                            uint8_t *a0, uint8_t *a1, uint8_t *R0, uint8_t *R1,
                                            const uint8_t *output, size_t output_size, size_t *output_length);

/**
 * @brief Low level wrapper function to call a driver for verify a signature with CBS.
 */
psa_status_t psa_bs_cbs_verify_signature(   uint8_t *signer_pub, size_t spub_size,
                                            const uint8_t *msg, size_t msg_size,
                                            const uint8_t *sig, size_t sig_size);