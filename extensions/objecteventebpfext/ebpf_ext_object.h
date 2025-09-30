#pragma once

#include "ebpf_ext.h"

/**
 * @brief Unregister OBJECT NPI providers.
 *
 */
void
ebpf_ext_unregister_ntos();

/**
 * @brief Register OBJECT NPI providers.
 *
 * @retval STATUS_SUCCESS Operation succeeded.
 * @retval STATUS_UNSUCCESSFUL Operation failed.
 */
NTSTATUS
ebpf_ext_register_ntos();