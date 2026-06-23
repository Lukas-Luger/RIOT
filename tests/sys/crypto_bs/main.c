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

// #include "thread.h"
// extern void print_stack_usage_metric(const char *name, void *stack, unsigned max_size);

extern uint8_t example_rsa_bs(void);

extern uint8_t example_rsa_fdh_bs(void);

int main(void)
{
    bool failed = false;
    uint8_t status;

    status = example_rsa_bs();
    // thread_t *me = thread_get_active();
    // print_stack_usage_metric(me->name, me->stack_start, me->stack_size);
    
    if (status != 0) {
        failed = true;
        printf("RSA blind signature failed: %d\n",
                status);
    }

    status = example_rsa_fdh_bs();
    
    if (status != 0) {
        failed = true;
        printf("RSA-FDH blind signature failed: %d\n",
                status);
    }

    if (failed) {
        puts("Tests failed...");
    }
    else {
        puts("All Done");
    }
    return 0;
    
}
