// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdint.h>

#include "snp_attest.h"

static void snp_report_print_u8_bytes(char *, uint8_t *, size_t);
static void snp_report_print_tcb_version(char *, union tcb_version);
static void snp_report_print_signature(char *, struct signature);

void
snp_report_print(struct snp_report *r)
{
        printf("\n{\n");
        printf("\tversion: %u\n", r->version);
        printf("\tguest_svn: %u\n", r->guest_svn);
        printf("\tpolicy: %lu\n", r->policy);
        snp_report_print_u8_bytes("family_id", r->family_id, 16);
        snp_report_print_u8_bytes("image_id", r->image_id, 16);
        printf("\tvmpl: %u\n", r->vmpl);
        printf("\tsignature_algo: %u\n", r->signature_algo);
        snp_report_print_tcb_version("platform_version", r->platform_version);
        printf("\tplatform_info: %lu\n", r->platform_info);
        printf("\tflags: %u\n", r->flags);
        printf("\treport_data: %s\n", (char *) r->report_data);
        snp_report_print_u8_bytes("measurement", r->measurement, 48);
        snp_report_print_u8_bytes("host_data", r->host_data, 32);
        snp_report_print_u8_bytes("id_key_digest", r->id_key_digest, 48);
        snp_report_print_u8_bytes("author_key_digest", r->author_key_digest, 48);
        snp_report_print_u8_bytes("report_id", r->report_id, 32);
        snp_report_print_u8_bytes("report_id_ma", r->report_id_ma, 32);
        snp_report_print_tcb_version("reported_tcb", r->reported_tcb);
        snp_report_print_u8_bytes("chip_id", r->chip_id, 64);
        snp_report_print_signature("signature", r->signature);
        printf("}\n");
}

static void
snp_report_print_u8_bytes(char *name, uint8_t *data, size_t size)
{
        int i;

        printf("\t%s: [", name);
        for (i = 0; i < size; i++) {
                printf("%u", data[i]);
                if (i < (size - 1))
                       printf(", ");
        }

        printf("]\n");
}

static void
snp_report_print_tcb_version(char *name, union tcb_version tcb)
{
        printf("\t%s: tcb_version {\n", name);
        printf("\t\tboot_loader: %u\n", tcb.boot_loader);
        printf("\t\ttee: %u\n", tcb.tee);
        printf("\t\tsnp: %u\n", tcb.snp);
        printf("\t\tmicrocode: %u\n", tcb.microcode);
        printf("\t}\n");
}

static void
snp_report_print_signature(char *name, struct signature sig)
{
        int i;

        printf("\t%s: signature {\n", name);
        printf("\t\tr: [");

        for (i = 0; i < 72; i++) {
                printf("%u", sig.r[i]);

                if (i < 71)
                        printf(", ");
        }
        printf("]\n");

        printf("\t\ts: [");

        for (i = 0; i < 72; i++) {
                printf("%u", sig.s[i]);

                if (i < 71)
                        printf(", ");
        }
        printf("]\n");

        printf("\t\treserved: [");

        for (i = 0; i < (512-144); i++) {
                printf("%u", sig.reserved[i]);

                if (i < (512-144-1))
                        printf(", ");
        }
        printf("]\n");

        printf("\t}\n");
}
