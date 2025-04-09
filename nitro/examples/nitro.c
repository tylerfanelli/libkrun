// SPDX-License-Identifier: Apache-2.0

#include <errno.h>
#include <stdio.h>
#include <libkrun.h>

int main(int argc, char *const argv[])
{
	int err, ctx_id;

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


	return 0;
}
