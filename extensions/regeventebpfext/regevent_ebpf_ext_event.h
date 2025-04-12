#pragma once

#include "ebpf_ext.h"

#define EBPF_REGEVENT_EXTENSION_POOL_TAG 'feER'

/**
 * @brief Unregister PROCESS NPI providers.
 *
 */
void
ebpf_ext_unregister_regevent();

/**
 * @brief Register PROCESS NPI providers.
 *
 * @retval STATUS_SUCCESS Operation succeeded.
 * @retval STATUS_UNSUCCESSFUL Operation failed.
 */
NTSTATUS
ebpf_ext_register_regevent();
