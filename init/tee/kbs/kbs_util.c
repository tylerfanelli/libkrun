// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>

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

char *
kbs_find_cookie(char *cookie_data, char *label)
{
        char *cookie_ptr;
        size_t label_len, cookie_len;

        label_len = strlen(label);
        cookie_len = strlen(cookie_data);

        cookie_ptr = cookie_data;
        for (int i = 0; i < (cookie_len - label_len); i++, cookie_ptr++) {
                if (strncmp(cookie_ptr, label, label_len) == 0)
                        return cookie_ptr;
        }

        return NULL;
}

int
kbs_read_cookie_val(char *label, char *buf)
{
        char *ptr;
        int ws;

        ws = 0;
        ptr = label;
        for (ptr = label; *ptr != '\0'; ptr++) {
                if (*ptr == ' ' || *ptr == '\t')
                        ws = 1;
                else if (ws == 1) {
                        strcpy(buf, ptr);

                        return 0;
                }
        }

        return -1;
}
