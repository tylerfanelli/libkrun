// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "kbs.h"

char *
tee_str(int tee)
{
        switch (tee) {
        case TEE_SEV:
                return "sev";
        case TEE_SGX:
                return "sgx";
        case TEE_SNP:
                return "snp";
        case TEE_TDX:
                return "tdx";
        default:
                printf("ERROR: tee_str(): Invalid input\n");
                return NULL;
        }
}
