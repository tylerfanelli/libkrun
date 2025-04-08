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

#endif // _LIBKRUN_H
