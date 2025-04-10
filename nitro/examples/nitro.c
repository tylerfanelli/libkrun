// SPDX-License-Identifier: Apache-2.0

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <libkrun.h>

static void print_help(char *const name)
{
    fprintf(stderr,
        "Usage: %s EIF_FILE_PATH ENCLAVE_CID\n"
        "OPTIONS: \n"
        "        -h    --help                Show help\n"
        "\n"
        "EIF_FILE_PATH:     the path of the Enclave Image Format file"
        "ENCLAVE_CID:       the context ID to be used with by the enclave\n",
        name
    );
}

int main(int argc, char *const argv[])
{
	int err, ctx_id;
    uint64_t cid;

    if (argc < 3) {
        putchar('\n');
        print_help(argv[0]);
        return -1;
    }

	ctx_id = krun_create_ctx();
	if (ctx_id < 0) {
		errno = -ctx_id;
		perror("Error creating nitro configuration context");
		return -1;
	}

    /*
     * These parameters must not be larger than what is allocated in
     * /etc/nitro_enclaves/allocator.yaml.
     */
    if (err = krun_set_vm_config(ctx_id, 1, 512)) {
        errno = -err;
        perror("Error configuring the number of vCPUs and/or the amount of RAM");
        return -1;
    }

    if (err = krun_set_nitro_eif_file(ctx_id, argv[1])) {
        errno = -err;
        perror("Error setting EIF file");
        return -1;
    }

    cid = (uint64_t) strtoull(argv[2], NULL, 10);
    if (err = krun_set_nitro_cid(ctx_id, cid)) {
        errno = -err;
        perror("Error setting enclave CID");
        return -1;
    }

	return 0;
}
