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
#include "edsign.h"

#define TIME_EVAL

#ifdef TIME_EVAL
#  include "ztimer.h"
#endif

static const uint8_t MESSAGE[] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
};

extern uint8_t generate_key_pair( uint8_t *priv_key_buffer, uint8_t *pub_key_buffer);
extern uint8_t bs_cbs_generate_commitment(uint8_t *r0, uint8_t *r1, const uint8_t *output, size_t size, size_t *length);
extern uint8_t bs_cbs_blind_message(const uint8_t *pubkey_data, size_t pubkey_data_len,
                                    const uint8_t *input, size_t input_length,
                                    const uint8_t *prandom, size_t prandom_length,
                                    uint8_t *R0_dash, uint8_t *R1_dash,
                                    uint8_t *a0, uint8_t *a1,
                                    const uint8_t *output, size_t output_size, size_t *output_length);
extern uint8_t bs_cbs_sign_message( uint8_t *priv_key, size_t key_bytes, const uint8_t *bmessage, size_t bsize,
                                    uint8_t *r0, uint8_t *r1, 
                                    uint8_t *bsignature, size_t bs_size, size_t *bs_length);
extern uint8_t bs_cbs_verify_signature( uint8_t *signer_pub, size_t spub_size,
                                        const uint8_t *msg, size_t msg_size,
                                        const uint8_t *sig, size_t sig_size);
extern uint8_t bs_cbs_unblind_signature(const uint8_t *input, size_t input_length,
                                        uint8_t *a0, uint8_t *a1, uint8_t *R0, uint8_t *R1,
                                        const uint8_t *output, size_t output_size, size_t *output_length);
uint8_t example_cbs_bs(void)
{
    uint8_t status = -1;
    size_t output_len;

    uint8_t r0[32];
    uint8_t r1[32];
    uint8_t R0[32];
    uint8_t R1[32];
    uint8_t a0[32];
    uint8_t a1[32];

    uint8_t priv_key[32];
    uint8_t pub_key[32];

    uint8_t commitment[64];
    uint8_t bmessage[64];

#ifdef TIME_EVAL
    ztimer_acquire(ZTIMER_USEC);
    ztimer_sleep(ZTIMER_USEC, 1000000);
    printf("{ \"cbs\": {");
    ztimer_now_t start = ztimer_now(ZTIMER_USEC);
#endif

    status = generate_key_pair(priv_key, pub_key);

#ifdef TIME_EVAL
    printf("\"key-gen\": %d, ", (int)(ztimer_now(ZTIMER_USEC) - start));
#endif

if (status != 0) {
        return status;
    }

#ifdef TIME_EVAL
    start = ztimer_now(ZTIMER_USEC);
#endif

    status = bs_cbs_generate_commitment(r0, r1, commitment, sizeof(commitment), &output_len);

#ifdef TIME_EVAL
    printf("\"com-gen\": %d, ", (int)(ztimer_now(ZTIMER_USEC) - start));
#endif

if (status != 0 || output_len != sizeof(commitment)) {
        return status;
    }

#ifdef TIME_EVAL
    start = ztimer_now(ZTIMER_USEC);
#endif
    status = bs_cbs_blind_message(pub_key, sizeof(pub_key),
                            MESSAGE, sizeof(MESSAGE),
                            commitment, sizeof(commitment),
                            R0, R1, a0, a1,
                            bmessage, sizeof(bmessage), &output_len);
#ifdef TIME_EVAL
    printf("\"blind\": %d, ", (int)(ztimer_now(ZTIMER_USEC) - start));
#endif
    if (status != 0 || output_len != sizeof(bmessage)) {
        return status;
    }

    uint8_t bsignature[33];
#ifdef TIME_EVAL
    start = ztimer_now(ZTIMER_USEC);
#endif
    status = bs_cbs_sign_message(priv_key, sizeof(priv_key), bmessage, sizeof(bmessage),
                                r0, r1, bsignature, sizeof(bsignature), &output_len);
#ifdef TIME_EVAL
    printf("\"sign\": %d, ", (int)(ztimer_now(ZTIMER_USEC) - start));
#endif
    if (status !=  0 || output_len != sizeof(bsignature)) {
        return status;
    }
   
    uint8_t signature[64];
#ifdef TIME_EVAL
    start = ztimer_now(ZTIMER_USEC);
#endif
    status = bs_cbs_unblind_signature(bsignature, sizeof(bsignature),
                                    a0, a1, R0, R1,
                                    signature, sizeof(signature), &output_len);
#ifdef TIME_EVAL
     printf("\"unblind\": %d, ", (int)(ztimer_now(ZTIMER_USEC) - start));
#endif
    if (status != 0 || output_len != sizeof(signature)) {
        return status;
    }

#ifdef TIME_EVAL
    start = ztimer_now(ZTIMER_USEC);
#endif
    status = bs_cbs_verify_signature(pub_key, sizeof(pub_key), MESSAGE, sizeof(MESSAGE),
                                signature, output_len);
#ifdef TIME_EVAL
    printf("\"verify\": %d } }\n", (int)(ztimer_now(ZTIMER_USEC) - start));
    ztimer_release(ZTIMER_USEC);
#endif

    if (status != 0) {
        return status;
    }

    return status;
}