// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "kbs.h"

int
kbs_request_marshal(char *json, int tee, char *workload_id)
{
        char *teestr;

        teestr = tee_str(tee);
        if (teestr == NULL)
                return -1;

        sprintf(json,
        "{\"extra-params\":\"{\\\"workload_id\\\":\\\"%s\\\"}\",\"tee\":\"%s\",\"version\":\"0.0.0\"}",
        workload_id,
        teestr);

        return 0;
}

int
kbs_challenge(CURL *curl, char *url, char *json, char *nonce)
{
        int ret;

        ret = kbs_curl_post(curl, url, (void *) json, (void *) nonce, KBS_CURL_REQ);
        if (ret < 0) {
                printf("ERROR: could not complete KBS challenge\n");
                return -1;
        }

        return 0;
}
