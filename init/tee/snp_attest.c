// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <curl/curl.h>
#include <linux/sev-guest.h>

#include "snp_attest.h"
#include "kbs/kbs.h"

static int snp_get_report(struct snp_report *, char *);

int
snp_attest(char *url, char *workload_id, char *passphrase)
{
        int ret;
        char json[1024], nonce[1024];
        CURL *curl;
        struct snp_report report;

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
        if (ret < 0) {
                printf("ERROR: Unable to complete KBS Challenge\n");
                return -1;
        }

        ret = snp_get_report(&report, nonce);
        if (ret < 0) {
                printf("ERROR: Unable to retrieve SNP attestation report\n");
                return -1;
        }

        ret = kbs_attest(curl, &report, passphrase);
        if (ret < 0) {
                printf("ERROR: Unable to attest SNP attestation report\n");
                return -1;
        }

        return 0;
}

static int
snp_get_report(struct snp_report *report, char *nonce)
{
        int ret, fd, rc;
        struct snp_report_req req;
        struct snp_report_resp resp;
        struct snp_guest_request_ioctl guest_req;
        struct msg_report_resp *report_resp;

        report_resp = (struct msg_report_resp *) &resp.data;
        rc = 1;

        /*
         * Initialize data structures.
         */
        memset(&req, 0, sizeof(req));
        memset(&resp, 0, sizeof(resp));
        memset(&report, 0, sizeof(report));
        memset(&guest_req, 0, sizeof(guest_req));

        strcpy((char *) req.user_data, nonce);

        guest_req.msg_version = 1;
        guest_req.req_data = (__u64) &req;
        guest_req.resp_data = (__u64) &resp;

        /*
         * Attestation report is retrieved from the SEV guest device.
         * (/dev/sev-guest)
         */
        fd = open(SEV_GUEST_DEV, O_RDWR);
        if (fd < 0) {
                printf("ERROR: Unable to open %s\n", SEV_GUEST_DEV);
                rc = 0;
                goto out;
        }

        /*
         * Issue ioctl(2) to SEV guest device.
         */
        ret = ioctl(fd, SNP_GET_REPORT, &guest_req);
        if (ret < 0) {
                printf("ERROR: ioctl(2) on %s\n", SEV_GUEST_DEV);
                rc = 0;
                goto close_err;
        }

        /*
         * Check that there wasn't a firmware error when generating the report.
         */
        ret = report_resp->status;
        if (ret != 0) {
                printf("ERROR: SEV guest device firmware error: %d\n", ret);
                rc = 0;
                goto close_err;
        } else if (report_resp->report_size > sizeof(*report)) {
                printf("ERROR: Attestation report is too large\n");
                rc = 0;
                goto close_err;
        }

        memcpy(&report, &report_resp->report, report_resp->report_size);

close_err:
        close(fd);
out:
        return rc;
}
