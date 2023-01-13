// SPDX-License-Identifier: Apache-2.0

#ifndef _KBS
#define _KBS

#include <curl/curl.h>

#include "../snp_attest.h"

// kbs_util.c
char *tee_str(int);
char *kbs_find_cookie(char *, char *);
int kbs_read_cookie_val(char *, char *);

enum tee {
        TEE_SEV,
        TEE_SGX,
        TEE_SNP,
        TEE_TDX,
};

enum curl_post_type {
        KBS_CURL_REQ,
        KBS_CURL_ATTEST,
        KBS_CURL_GET_KEY,
};

// kbs_types.c
int kbs_request_marshal(char *, int, char *);
int kbs_challenge(CURL *, char *, char *, char *);
int kbs_attest(CURL *, char *, struct snp_report *, uint8_t *, size_t);
int kbs_get_key(CURL *, char *, char *);

// kbs_curl.c
int kbs_curl_post(CURL *, char *, char *, char *, int);
int kbs_curl_get(CURL *, char *, char *, int);

#endif /* _KBS */
