#pragma once

#include "ebpf_ext.h"

/**
 * @brief Unregister THREAD NPI providers.
 *
 */
void
ntos_ebpf_ext_thread_unregister_providers();

/**
 * @brief Register THREAD NPI providers.
 *
 * @retval STATUS_SUCCESS Operation succeeded.
 * @retval STATUS_UNSUCCESSFUL Operation failed.
 */
NTSTATUS
ntos_ebpf_ext_thread_register_providers();