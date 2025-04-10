// SPDX-License-Identifier: Apache-2.0

#include <errno.h>
#include <stdio.h>
#include <libkrun.h>

static void print_help(char *const name)
{
    fprintf(stderr,
        "Usage: %s EIF_FILE_PATH\n"
        "OPTIONS: \n"
        "        -h    --help                Show help\n"
        "\n"
        "EIF_FILE_PATH:     the path of the Enclave Image Format file\n",
        name
    );
}

int main(int argc, char *const argv[])
{
	int err, ctx_id;

    if (argc != 2) {
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

	return 0;
}
