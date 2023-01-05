// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <curl/curl.h>

#include "snp_attest.h"
#include "kbs/kbs.h"

int
snp_attest(char *url, char *workload_id)
{
        int ret;
        char json[1024], nonce[1024];
        CURL *curl;

        ret = kbs_request_marshal(json, TEE_SNP, workload_id);
        if (ret < 0) {
                printf("ERROR: KBS request could not be marshalled\n");
                return -1;
        }

        curl = curl_easy_init();
        if (curl == NULL) {
                printf("ERROR: Unable to initalize cURL instance\n");
                return -1;
        }

        ret = kbs_challenge(curl, url, json, nonce);

        printf("\nHERE\n");

        return 0;
}
