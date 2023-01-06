// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "kbs.h"

static void kbs_attestation_marshal(struct snp_report *, char *);
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

        ret = kbs_curl_post(curl, url, (void *) json, (void *) nonce, KBS_CURL_REQ);
        if (ret < 0) {
                printf("ERROR: could not complete KBS challenge\n");
                return -1;
        }

        return 0;
}

int
kbs_attest(CURL *curl, struct snp_report *report, char *passphrase)
{
        char json[0x4000];      // 4page report size

        kbs_attestation_marshal(report, json);

        return 0;
}

static void
kbs_attestation_marshal(struct snp_report *report, char *json)
{
        char buf[4096];

        sprintf(buf, "{");
        strcpy(json, buf);

        sprintf(buf, "\"version\":0,");
        strcat(json, buf);

        sprintf(buf, "\"guest_svn\":0,");
        strcat(json, buf);

        sprintf(buf, "\"policy\":0,");
        strcat(json, buf);

        kbs_attestation_marshal_bytes(json, "family_id", (uint8_t *) report->family_id, 16);
        strcat(json, ",");

        kbs_attestation_marshal_bytes(json, "image_id", (uint8_t *) report->image_id, 16);
        strcat(json, ",");

        sprintf(buf, "\"vmpl\":0,"),
        strcat(json, buf);

        sprintf(buf, "\"sig_algo\":0,");
        strcat(json, buf);

        kbs_attestation_marshal_tcb(json, "current_tcb", &report->current_tcb);
        strcat(json, ",");

        sprintf(buf, "\"plat_info\":0,");
        strcat(json, buf);

        sprintf(buf, "\"_author_key_en\":0,");
        strcat(json, buf);

        sprintf(buf, "\"_reserved_0\":0,");
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

        kbs_attestation_marshal_tcb(json, "reported_tcb", &report->reported_tcb);
        strcat(json, ",");

        kbs_attestation_marshal_bytes(json, "_reserved_1",
                (uint8_t *) report->_reserved_1, 24);
        strcat(json, ",");

        kbs_attestation_marshal_bytes(json, "chip_id",
                (uint8_t *) report->chip_id, 64);
        strcat(json, ",");

        kbs_attestation_marshal_tcb(json, "committed_tcb", &report->committed_tcb);
        strcat(json, ",");

        sprintf(buf, "\"current_build\":0,");
        strcat(json, buf);

        sprintf(buf, "\"current_minor\":0,");
        strcat(json, buf);

        sprintf(buf, "\"current_major\":0,");
        strcat(json, buf);

        sprintf(buf, "\"_reserved_2\":0,");
        strcat(json, buf);

        sprintf(buf, "\"committed_build\":0,");
        strcat(json, buf);

        sprintf(buf, "\"committed_minor\":0,");
        strcat(json, buf);

        sprintf(buf, "\"committed_major\":0,");
        strcat(json, buf);

        sprintf(buf, "\"_reserved_3\":0,");
        strcat(json, buf);

        kbs_attestation_marshal_tcb(json, "launch_tcb", &report->launch_tcb);
        strcat(json, ",");

        kbs_attestation_marshal_bytes(json, "_reserved_4",
                (uint8_t *) report->_reserved_4, 168);
        strcat(json, ",");

        kbs_attestation_marshal_signature(json, &report->signature);

        strcat(json, "}");
}

static void
kbs_attestation_marshal_tcb(char *json, char *name, union tcb_version *tcb)
{
        char buf[4096];

        sprintf(buf, "\"%s\":{", name);
        strcat(json, buf);

        sprintf(buf, "\"boot_loader\":0,");
        strcat(json, buf);

        sprintf(buf, "\"tee\":0,");
        strcat(json, buf);

        kbs_attestation_marshal_bytes(json, "reserved", tcb->reserved, 4);
        strcat(json, ",");

        sprintf(buf, "\"snp\":0,");
        strcat(json, buf);

        sprintf(buf, "\"microcode\":0}");
        strcat(json, buf);

        return;
}

static void
kbs_attestation_marshal_bytes(char *json, char *label, uint8_t *data, size_t sz)
{
        uint8_t byte;
        char buf[4096];

        sprintf(buf, "\"%s\":[", label);
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

        sprintf(buf, "\"signature\":{");
        strcat(json, buf);

        kbs_attestation_marshal_bytes(json, "r", sig->r, 72);
        kbs_attestation_marshal_bytes(json, "s", sig->s, 72);

        strcat(json, "}");
}
