/*
 * SPDX-FileCopyrightText: 2025 TU Dresden
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/**
 * @ingroup     tests
 * @{
 *
 * @brief       Tests the PSA blind signature schemes
 *
 * @author      Lukas Luger <lukas.luger@mailbox.tu-dresden.de>
 *
 * @}
 */

#include <stdio.h>
#include <stdint.h>
#include "psa/crypto.h"

#define TIME_EVAL

#ifdef TIME_EVAL
#  include "ztimer.h"
#endif

static const uint8_t MESSAGE[] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
};

#define ECC_KEY_SIZE (255)
#define ECC_KEY_TYPE (PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS))

psa_status_t example_cbs_bs(void)
{
    psa_status_t status = PSA_ERROR_NOT_PERMITTED;
    psa_blind_sign_ctx_t signer_ctx = { 0 };
    psa_blind_sign_ctx_t user_ctx = { 0 };

    psa_key_id_t key_id = 0;
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_key_usage_t usage = PSA_KEY_USAGE_VERIFY_MESSAGE | PSA_KEY_USAGE_SIGN_MESSAGE;
    psa_algorithm_t algo = PSA_ALG_CBS;    

    psa_set_key_algorithm(&attr, algo);
    psa_set_key_usage_flags(&attr, usage);
    psa_set_key_bits(&attr, ECC_KEY_SIZE);
    psa_set_key_type(&attr, ECC_KEY_TYPE);

#ifdef TIME_EVAL
    ztimer_acquire(ZTIMER_USEC);
    ztimer_sleep(ZTIMER_USEC, 1000000);
    printf("{ \"cbs\": {");
    ztimer_now_t start = ztimer_now(ZTIMER_USEC);
#endif
    status = psa_generate_key(&attr, &key_id);
#ifdef TIME_EVAL
    printf("\"key-gen\": %d, ", (int)(ztimer_now(ZTIMER_USEC) - start));
#endif
    if (status != PSA_SUCCESS) {
        psa_destroy_key(key_id);
        return status;
    }
    
    status = psa_blindsig_user_setup(&user_ctx, algo, 0);
    if (status != PSA_SUCCESS) {
        psa_destroy_key(key_id);
        return status;
    }

    uint8_t commitment[64];
    size_t output_len;
#ifdef TIME_EVAL
    start = ztimer_now(ZTIMER_USEC);
#endif
    status = psa_blindsig_signer_setup(&signer_ctx, algo, commitment, sizeof(commitment), &output_len);
#ifdef TIME_EVAL
    printf("\"com-gen\": %d, ", (int)(ztimer_now(ZTIMER_USEC) - start));
#endif
    if (status != PSA_SUCCESS || output_len != sizeof(commitment)) {
        psa_destroy_key(key_id);
        if (status == PSA_SUCCESS) {
            return PSA_ERROR_DATA_INVALID;
        }
        else {
            return status;
        }
    }

    uint8_t bmessage[64];
#ifdef TIME_EVAL
    start = ztimer_now(ZTIMER_USEC);
#endif
    status = psa_blindsig_blind_message(&user_ctx, key_id,
                                        MESSAGE, sizeof(MESSAGE),
                                        commitment, sizeof(commitment),
                                        bmessage, sizeof(bmessage),
                                        &output_len);
#ifdef TIME_EVAL
    printf("\"blind\": %d, ", (int)(ztimer_now(ZTIMER_USEC) - start));
#endif
    if (status != PSA_SUCCESS || output_len != sizeof(bmessage)) {
        psa_destroy_key(key_id);
        if (status == PSA_SUCCESS) {
            return PSA_ERROR_DATA_INVALID;
        }
        else {
            return status;
        }
    }

    uint8_t bsignature[33];
#ifdef TIME_EVAL
    start = ztimer_now(ZTIMER_USEC);
#endif
    status = psa_blindsig_sign(&signer_ctx, key_id, bmessage, sizeof(bmessage),
                               bsignature, sizeof(bsignature), &output_len);
#ifdef TIME_EVAL
    printf("\"sign\": %d, ", (int)(ztimer_now(ZTIMER_USEC) - start));
#endif
    if (status !=  PSA_SUCCESS || output_len != sizeof(bsignature)) {
        psa_destroy_key(key_id);
        if (status == PSA_SUCCESS) {
            return PSA_ERROR_DATA_INVALID;
        }
        else {
            return status;
        }
    }
   
    uint8_t signature[64];
#ifdef TIME_EVAL
    start = ztimer_now(ZTIMER_USEC);
#endif
    status = psa_blindsig_unblind(&user_ctx, key_id, bsignature,
                                  sizeof(bsignature), signature,
                                  sizeof(signature), &output_len);
#ifdef TIME_EVAL
     printf("\"unblind\": %d, ", (int)(ztimer_now(ZTIMER_USEC) - start));
#endif
    if (status != PSA_SUCCESS || output_len != sizeof(signature)) {
        psa_destroy_key(key_id);
        if (status == PSA_SUCCESS) {
            return PSA_ERROR_DATA_INVALID;
        }
        else {
            return status;
        }
    }

#ifdef TIME_EVAL
    start = ztimer_now(ZTIMER_USEC);
#endif
    status = psa_verify_message(key_id, algo, MESSAGE, sizeof(MESSAGE),
                                signature, output_len);
#ifdef TIME_EVAL
    printf("\"verify\": %d } }\n", (int)(ztimer_now(ZTIMER_USEC) - start));
    ztimer_release(ZTIMER_USEC);
#endif

    if (status != PSA_SUCCESS) {
        psa_destroy_key(key_id);
        return status;
    }

    return status;
}