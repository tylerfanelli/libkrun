// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>
#include <curl/curl.h>

#include "kbs.h"

static CURLcode kbs_curl_set_headers(CURL *, char *);
static int KBS_CURL_ERR(char *);
size_t curl_write(void *, size_t, size_t, void *);

static int kbs_curl_post_request(CURL *, char *, char *, char *);

int
kbs_curl_post(CURL *curl, char *url, void *in, void *out, int type)
{
        CURLcode code;

        if (!in)
                return KBS_CURL_ERR("Input argument NULL");

        if (!out)
                return KBS_CURL_ERR("Output argument NULL");

        code = kbs_curl_set_headers(curl, NULL);
        if (code != CURLE_OK)
                return KBS_CURL_ERR("CURLOPT_HTTPHEADER");

        code = curl_easy_setopt(curl, CURLOPT_POST, 1L);
        if (code != CURLE_OK)
                return KBS_CURL_ERR("CURLOPT_POST");

        code = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write);
        if (code != CURLE_OK)
                return KBS_CURL_ERR("CURLOPT_WRITEFUNCTION");

        switch (type) {
        case KBS_CURL_REQ:
                return kbs_curl_post_request(curl, url, (char *) in,
                        (char *) out);
        default:
                return KBS_CURL_ERR("Type argument invalid");
        }
}

static CURLcode
kbs_curl_set_headers(CURL *curl, char *session)
{
        struct curl_slist *slist;
        char session_buf[100];

        slist = NULL;
        slist = curl_slist_append(slist, "Accept: application/json");
        slist = curl_slist_append(slist,
                "Content-Type: application/json; charset=utf-8");

        if (session) {
                sprintf(session_buf, "Cookie: session_id=%s", session);
                curl_slist_append(slist, session_buf);
        }

        return curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
}

static int
kbs_curl_post_request(CURL *curl, char *url, char *req, char *nonce)
{
        CURLcode code;
        char req_url[100];

        sprintf(req_url, "%s/kbs/v0/auth", url);

        code = curl_easy_setopt(curl, CURLOPT_URL, req_url);
        if (code != CURLE_OK)
                return KBS_CURL_ERR("CURLOPT_URL");

        code = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long) strlen(req));
        if (code != CURLE_OK)
                return KBS_CURL_ERR("CURLOPT_POSTFIELDSIZE");

        code = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req);
        if (code != CURLE_OK)
                return KBS_CURL_ERR("CURLOPT_POSTFIELDS");

        code = curl_easy_setopt(curl, CURLOPT_WRITEDATA, nonce);
        if (code != CURLE_OK)
                return KBS_CURL_ERR("CURLOPT_WRITEDATA");

        code = curl_easy_perform(curl);
        if (code != CURLE_OK && code != CURLE_WRITE_ERROR)
                return KBS_CURL_ERR("CURL_EASY_PERFORM");

        return 0;
}

static int
KBS_CURL_ERR(char *errmsg)
{
        printf("ERROR (kbs_curl_post): %s\n", errmsg);

        return -1;
}

size_t
curl_write(void *data, size_t size, size_t nmemb, void *userp)
{
        strcpy((char *) userp, (char *) data);

        return size;
}
