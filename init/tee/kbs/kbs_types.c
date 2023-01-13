// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "kbs.h"

static void kbs_attestation_marshal(struct snp_report *, uint8_t *, size_t, char *);
static void kbs_attestation_marshal_tcb(char *, char *, union tcb_version *);
static void kbs_attestation_marshal_signature(char *, struct signature *);
static void kbs_attestation_marshal_bytes(char *, char *, uint8_t *, size_t);

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

        ret = kbs_curl_post(curl, url, json, nonce, KBS_CURL_REQ);
        if (ret < 0) {
                printf("ERROR: could not complete KBS challenge\n");
                return -1;
        }

        printf("nonce: |%s|\n", nonce);

        return 0;
}

int
kbs_attest(CURL *curl, char *url, struct snp_report *report, uint8_t *certs,
        size_t certs_size)
{
        int ret;
        char json[0x3000], errmsg[200];

        kbs_attestation_marshal(report, certs, certs_size, json);
        struct snp_report x;

        memset((void *) &x, 0, sizeof(struct snp_report));

        kbs_attestation_marshal(&x, certs, certs_size, json);
        strcpy(errmsg, "");

        ret = kbs_curl_post(curl, url, json, errmsg, KBS_CURL_ATTEST);
        if (ret < 0) {
                printf("ERROR: could not complete KBS attestation\n");
                return -1;
        }

        if (strcmp(errmsg, "") != 0)
                return -1;

        return 0;
}

int
kbs_get_key(CURL *curl, char *url, char *passphrase)
{
        int ret;

        ret = kbs_curl_get(curl, url, passphrase, KBS_CURL_GET_KEY);
        if (ret < 0) {
                printf("ERROR: could not complete KBS key retrieval\n");
                return -1;
        }

        return 0;
}

static void
kbs_attestation_marshal(struct snp_report *report, uint8_t *certs,
        size_t certs_size, char *json)
{
        char buf[4096];

        sprintf(buf, "{");
        strcpy(json, buf);

        sprintf(buf, "\"tee-pubkey\":{\"kty\":\"\",\"alg\":\"\",\"k\":\"\"},");
        strcat(json, buf);

        sprintf(buf, "\"tee-evidence\":\"{\\\"report\\\":\\\"{");
        strcat(json, buf);

        sprintf(buf, "\\\\\\\"version\\\\\\\":%u,", report->version);
        strcat(json, buf);

        sprintf(buf, "\\\\\\\"guest_svn\\\\\\\":%u,", report->guest_svn);
        strcat(json, buf);

        sprintf(buf, "\\\\\\\"policy\\\\\\\":%lu,", report->policy);
        strcat(json, buf);

        kbs_attestation_marshal_bytes(json, "family_id",
                (uint8_t *) report->family_id, 16);
        strcat(json, ",");

        kbs_attestation_marshal_bytes(json, "image_id",
                (uint8_t *) report->image_id, 16);
        strcat(json, ",");

        sprintf(buf, "\\\\\\\"vmpl\\\\\\\":%u,", report->vmpl),
        strcat(json, buf);

        sprintf(buf, "\\\\\\\"sig_algo\\\\\\\":%u,", report->signature_algo);
        strcat(json, buf);

        kbs_attestation_marshal_tcb(json, "current_tcb", &report->current_tcb);
        strcat(json, ",");

        sprintf(buf, "\\\\\\\"plat_info\\\\\\\":%lu,", report->platform_info);
        strcat(json, buf);

        sprintf(buf, "\\\\\\\"_author_key_en\\\\\\\":%u,",
                report->author_key_en);
        strcat(json, buf);

        sprintf(buf, "\\\\\\\"_reserved_0\\\\\\\":%u,", report->_reserved_0);
        strcat(json, buf);

        kbs_attestation_marshal_bytes(json, "report_data",
                (uint8_t *) report->report_data, 64);
        strcat(json, ",");

        kbs_attestation_marshal_bytes(json, "measurement",
                (uint8_t *) report->measurement, 48);
        strcat(json, ",");

        kbs_attestation_marshal_bytes(json, "host_data",
                (uint8_t *) report->host_data, 32);
        strcat(json, ",");

        kbs_attestation_marshal_bytes(json, "id_key_digest",
                (uint8_t *) report->id_key_digest, 48);
        strcat(json, ",");

        kbs_attestation_marshal_bytes(json, "author_key_digest",
                (uint8_t *) report->author_key_digest, 48);
        strcat(json, ",");

        kbs_attestation_marshal_bytes(json, "report_id",
                (uint8_t *) report->report_id, 32);
        strcat(json, ",");

        kbs_attestation_marshal_bytes(json, "report_id_ma",
                (uint8_t *) report->report_id_ma, 32);
        strcat(json, ",");

        kbs_attestation_marshal_tcb(json, "reported_tcb",
                &report->reported_tcb);
        strcat(json, ",");

        kbs_attestation_marshal_bytes(json, "_reserved_1",
                (uint8_t *) report->_reserved_1, 24);
        strcat(json, ",");

        kbs_attestation_marshal_bytes(json, "chip_id",
                (uint8_t *) report->chip_id, 64);
        strcat(json, ",");

        kbs_attestation_marshal_tcb(json, "committed_tcb",
                &report->committed_tcb);
        strcat(json, ",");

        sprintf(buf, "\\\\\\\"current_build\\\\\\\":%u,",
                report->current_build);
        strcat(json, buf);

        sprintf(buf, "\\\\\\\"current_minor\\\\\\\":%u,",
                report->current_minor);
        strcat(json, buf);

        sprintf(buf, "\\\\\\\"current_major\\\\\\\":%u,",
                report->current_major);
        strcat(json, buf);

        sprintf(buf, "\\\\\\\"_reserved_2\\\\\\\":%u,", report->_reserved_2);
        strcat(json, buf);

        sprintf(buf, "\\\\\\\"committed_build\\\\\\\":%u,",
                report->committed_build);
        strcat(json, buf);

        sprintf(buf, "\\\\\\\"committed_minor\\\\\\\":%u,",
                report->committed_minor);
        strcat(json, buf);

        sprintf(buf, "\\\\\\\"committed_major\\\\\\\":%u,",
                report->committed_major);
        strcat(json, buf);

        sprintf(buf, "\\\\\\\"_reserved_3\\\\\\\":%u,", report->_reserved_3);
        strcat(json, buf);

        kbs_attestation_marshal_tcb(json, "launch_tcb", &report->launch_tcb);
        strcat(json, ",");

        kbs_attestation_marshal_bytes(json, "_reserved_4",
                (uint8_t *) report->_reserved_4, 168);
        strcat(json, ",");

        kbs_attestation_marshal_signature(json, &report->signature);

        strcat(json, "}\\\",");
        strcat(json, "\\\"cert_chain\\\":\\\"test\\\"}\"}");
}

static void
kbs_attestation_marshal_tcb(char *json, char *name, union tcb_version *tcb)
{
        char buf[4096];

        sprintf(buf, "\\\\\\\"%s\\\\\\\":{", name);
        strcat(json, buf);

        sprintf(buf, "\\\\\\\"boot_loader\\\\\\\":%u,", tcb->boot_loader);
        strcat(json, buf);

        sprintf(buf, "\\\\\\\"tee\\\\\\\":%u,", tcb->tee);
        strcat(json, buf);

        kbs_attestation_marshal_bytes(json, "reserved", tcb->reserved, 4);
        strcat(json, ",");

        sprintf(buf, "\\\\\\\"snp\\\\\\\":%u,", tcb->snp);
        strcat(json, buf);

        sprintf(buf, "\\\\\\\"microcode\\\\\\\":%u}", tcb->microcode);
        strcat(json, buf);

        return;
}

static void
kbs_attestation_marshal_bytes(char *json, char *label, uint8_t *data, size_t sz)
{
        uint8_t byte;
        char buf[4096];

        sprintf(buf, "\\\\\\\"%s\\\\\\\":[", label);
        strcat(json, buf);

        for (int i = 0; i < sz; i++) {
                byte = data[i];

                sprintf(buf, "%u", byte);
                if (i < (sz - 1))
                        strcat(buf, ",");

                strcat(json, buf);
        }

        strcat(json, "]");
}

static void
kbs_attestation_marshal_signature(char *json, struct signature *sig)
{
        char buf[4096];

        sprintf(buf, "\\\\\\\"signature\\\\\\\":{");
        strcat(json, buf);

        kbs_attestation_marshal_bytes(json, "r", sig->r, 72);
        strcat(json, ",");

        kbs_attestation_marshal_bytes(json, "s", sig->s, 72);

        strcat(json, "}");
}
