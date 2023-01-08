// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <curl/curl.h>

#include "kbs.h"

static CURLcode kbs_curl_set_headers(CURL *, char *);
static int KBS_CURL_ERR(char *);
size_t curl_write(void *, size_t, size_t, void *);

int
kbs_curl_post(CURL *curl, char *url, char *in, char *out, int type)
{
        int ret;
        CURLcode code;
        char full_url[100], *cookie_label, session_id[100];
        struct curl_slist *cookies;

        if (!in)
                return KBS_CURL_ERR("Input argument NULL");

        if (!out)
                return KBS_CURL_ERR("Output argument NULL");

        code = curl_easy_setopt(curl, CURLOPT_POST, 1L);
        if (code != CURLE_OK)
                return KBS_CURL_ERR("CURLOPT_POST");

        code = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write);
        if (code != CURLE_OK)
                return KBS_CURL_ERR("CURLOPT_WRITEFUNCTION");

        cookies = NULL;
        if (type == KBS_CURL_REQ) {
                sprintf(full_url, "%s/kbs/v0/auth", url);
                code = curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");
                if (code != CURLE_OK)
                        return KBS_CURL_ERR("CURLOPT_COOKIEFILE");

                code = kbs_curl_set_headers(curl, NULL);
                if (code != CURLE_OK)
                        return KBS_CURL_ERR("CURLOPT_HTTPHEADER");
        } else {
                sprintf(full_url, "%s/kbs/v0/attest", url);

                code = curl_easy_getinfo(curl, CURLINFO_COOKIELIST, &cookies);
                if (code != CURLE_OK)
                        return KBS_CURL_ERR("CURLOPT_COOKIELIST");

                cookie_label = NULL;
                while (cookies) {
                        cookie_label = kbs_find_cookie(cookies->data, "session_id");
                        if (cookie_label)
                                break;
                        cookies = cookies->next;
                }

                if (cookie_label == NULL)
                        return KBS_CURL_ERR("No session_id cookie found");

                ret = kbs_read_cookie_val(cookie_label, session_id);
                if (ret < 0)
                        return KBS_CURL_ERR("No session_id value for cookie");

                code = kbs_curl_set_headers(curl, (char *) session_id);
                if (code != CURLE_OK)
                        return KBS_CURL_ERR("CURLOPT_HTTPHEADER");                
        }

        code = curl_easy_setopt(curl, CURLOPT_URL, full_url);
        if (code != CURLE_OK)
                return KBS_CURL_ERR("CURLOPT_URL");

        code = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long) strlen(in));
        if (code != CURLE_OK)
                return KBS_CURL_ERR("CURLOPT_POSTFIELDSIZE");

        code = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, in);
        if (code != CURLE_OK)
                return KBS_CURL_ERR("CURLOPT_POSTFIELDS");

        code = curl_easy_setopt(curl, CURLOPT_WRITEDATA, out);
        if (code != CURLE_OK)
                return KBS_CURL_ERR("CURLOPT_WRITEDATA");

        code = curl_easy_perform(curl);
        if (code != CURLE_OK && code != CURLE_WRITE_ERROR)
                return KBS_CURL_ERR("CURL_EASY_PERFORM");

        return 0;
}

static CURLcode
kbs_curl_set_headers(CURL *curl, char *session)
{
        struct curl_slist *slist;
        char session_buf[0x1000];

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

static inline int
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
