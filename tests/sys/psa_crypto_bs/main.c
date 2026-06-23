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
#include <stdbool.h>
#include "psa/crypto.h"
// #include "thread.h"
// extern void print_stack_usage_metric(const char *name, void *stack, unsigned max_size);

extern psa_status_t example_rsa_bs(void);

extern psa_status_t example_rsa_fdh_bs(void);

int main(void)
{
   bool failed = false;
    psa_status_t status;

    psa_crypto_init();
    puts("PSA RSA Example");
    status = example_rsa_bs();
    // thread_t *me = thread_get_active();
    // print_stack_usage_metric(me->name, me->stack_start, me->stack_size);
    if (status != PSA_SUCCESS) {
        failed = true;
        printf("RSA blind signature failed: %s\n",
                psa_status_to_humanly_readable(status));
    }
    status = example_rsa_fdh_bs();
    if (status != PSA_SUCCESS) {
        failed = true;
        printf("RSA-FDH blind signature failed: %s\n",
                psa_status_to_humanly_readable(status));
    }


    if (failed) {
        puts("Tests failed...");
    }
    else {
        puts("All Done");
    }
    return 0;
    
}
