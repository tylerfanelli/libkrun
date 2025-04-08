// SPDX-License-Identifier: Apache-2.0

#include <errno.h>
#include <stdio.h>
#include <libkrun.h>

int main(int argc, char *const argv[])
{
	int ctx_id;

	ctx_id = krun_create_ctx();
	if (ctx_id < 0) {
		errno = -ctx_id;
		perror("Error creating nitro configuration context");
		return -1;
	}

	return 0;
}
