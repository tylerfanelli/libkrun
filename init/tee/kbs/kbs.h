// SPDX-License-Identifier: Apache-2.0

#ifndef _KBS
#define _KBS

#include <curl/curl.h>

#include "../snp_attest.h"

// kbs_util.c
char *tee_str(int);

enum tee {
        TEE_SEV,
        TEE_SGX,
        TEE_SNP,
        TEE_TDX,
};

enum curl_post_type {
        KBS_CURL_REQ,
};

// kbs_types.c
int kbs_request_marshal(char *, int, char *);
int kbs_challenge(CURL *, char *, char *, char *);
int kbs_attest(CURL *, struct snp_report *, char *);

// kbs_curl.c
int kbs_curl_post(CURL *, char *, void *, void *, int);

#endif /* _KBS */
