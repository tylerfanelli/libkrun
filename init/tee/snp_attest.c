// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#include <sys/ioctl.h>
#include <curl/curl.h>
#include <linux/sev-guest.h>

#include "snp_attest.h"
#include "kbs/kbs.h"

static int snp_get_ext_report(const uint8_t *, size_t, struct snp_report *,
        uint8_t **, size_t *);

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

        uint8_t *certs;
        size_t certs_size;

        certs = NULL;
        certs_size = 0;

        ret = snp_get_ext_report((uint8_t *) nonce, strlen(nonce) + 1, &report,
                &certs, &certs_size);
        if (ret < 0) {
                printf("ERROR: Unable to retrieve SNP attestation report\n");
                return -1;
        }

        ret = kbs_attest(curl, url, &report);
        if (ret < 0) {
                printf("ERROR: Unable to attest SNP attestation report\n");
                return -1;
        }

        curl_easy_reset(curl);

        ret = kbs_get_key(curl, url, passphrase);
        if (ret < 0) {
                printf("ERROR: Unable to retrieve key from KBS server\n");
                return -1;
        }

        return 0;
}

static int
snp_get_ext_report(const uint8_t *data, size_t data_size,
        struct snp_report *report, uint8_t **certs, size_t *certs_size)
{
	int rc = EXIT_FAILURE;
	int fd = -1;
	struct snp_ext_report_req req;
	struct snp_report_resp resp;
	struct snp_guest_request_ioctl guest_req;
	struct msg_report_resp *report_resp = (struct msg_report_resp *)&resp.data;
	struct cert_table certs_data;
	size_t page_size = 0, nr_pages = 0;

	if (!report || !certs || !certs_size) {
                printf("report || certs || certs_size == NULL\n");
		rc = EINVAL;
		goto out;
	}

	if (data && (data_size > sizeof(req.data.user_data) || data_size == 0)) {
		rc = EINVAL;
		goto out;
	}

	/* Initialize data structures */
	memset(&req, 0, sizeof(req));
#if 1
	req.certs_address = (__u64)-1;	/* Invalid, non-zero address */
#endif
	if (data)
		memcpy(&req.data.user_data, data, data_size);

	memset(&resp, 0, sizeof(resp));

	memset(&guest_req, 0, sizeof(guest_req));
	guest_req.msg_version = 1;
	guest_req.req_data = (__u64) &req;
	guest_req.resp_data = (__u64) &resp;

	memset(&certs_data, 0, sizeof(certs_data));

	/* Open the sev-guest device */
	errno = 0;
	fd = open(SEV_GUEST_DEV, O_RDWR);
	if (fd == -1) {
		rc = errno;
		perror("open");
		goto out;
	}

	/* Query the size of the stored certificates */
	errno = 0;
	rc = ioctl(fd, SNP_GET_EXT_REPORT, &guest_req);
	if (rc == -1 && guest_req.fw_err != 0x100000000) {
		rc = errno;
		perror("ioctl");
		fprintf(stderr, "firmware error %#llx\n", guest_req.fw_err);
		fprintf(stderr, "report error %#x\n", report_resp->status);
		fprintf(stderr, "certs_len %#x\n", req.certs_len);
		goto out_close;
	}

	if (req.certs_len == 0) {
		fprintf(stderr, "The cert chain storage is empty.\n");
		rc = ENODATA;
		goto out_close;
	}

	/* The certificate storage is always page-aligned */
	page_size = sysconf(_SC_PAGESIZE);
	nr_pages = req.certs_len/page_size;
	if (req.certs_len % page_size != 0)
		nr_pages++;	/* Just to be safe */

	certs_data.entry = calloc(page_size, nr_pages);
	if (!certs_data.entry) {
		rc = ENOMEM;
		errno = rc;
		perror("calloc");
		goto out_close;
	}

	/* Retrieve the cert chain */
	req.certs_address = (__u64)certs_data.entry;
	errno = 0;
	rc = ioctl(fd, SNP_GET_EXT_REPORT, &guest_req);
	if (rc == -1) {
		rc = errno;
		perror("ioctl");
		fprintf(stderr, "errno is %u\n", errno);
		fprintf(stderr, "firmware error %#llx\n", guest_req.fw_err);
		fprintf(stderr, "report error %x\n", report_resp->status);
		goto out_free;
	}

	/* Check that the report was successfully generated */
	if (report_resp->status != 0 ) {
		fprintf(stderr, "firmware error %x\n", report_resp->status);
		rc = report_resp->status;
		goto out_free;
	}
	else if (report_resp->report_size > sizeof(*report)) {
		fprintf(stderr, "report size is %u bytes (expected %lu)!\n",
			report_resp->report_size, sizeof(*report));
		rc = EFBIG;
		goto out_free;
	}

	memcpy(report, &report_resp->report, report_resp->report_size);
	*certs = (uint8_t *)certs_data.entry;
	*certs_size = req.certs_len;
	rc = EXIT_SUCCESS;

out_free:
	if (rc != EXIT_SUCCESS && certs_data.entry) {
		free(certs_data.entry);
		certs_data.entry = NULL;
	}

out_close:
	if (fd > 0) {
		close(fd);
		fd = -1;
	}
out:
	return rc;
}
