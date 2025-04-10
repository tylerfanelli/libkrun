#include <inttypes.h>
#include <stdbool.h>
#include <unistd.h>

#ifndef _LIBKRUN_H
#define _LIBKRUN_H

/**
 * Creates a configuration context.
 *
 * Returns:
 *  The context ID on success or a negative error number on failure.
 */
int32_t krun_create_ctx();

/**
 * Sets the basic configuration parameters for the nitro enclave.
 *
 * Arguments:
 *  "ctx_id"    - the configuration context ID.
 *  "num_vcpus" - the number of vCPUs.
 *  "ram_mib"   - the amount of RAM in MiB.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_set_vm_config(uint32_t ctx_id, uint8_t num_vcpus, uint32_t ram_mib);

/**
 * Sets the path of the Enclave Image Format file to be used.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_set_nitro_eif_file(uint32_t ctx_id, const char *c_eif_path);

#endif // _LIBKRUN_H
