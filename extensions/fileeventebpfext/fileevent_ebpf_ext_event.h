#pragma once

#include "ebpf_ext.h"

#define EBPF_FILEEVENT_EXTENSION_POOL_TAG 'feEN'

/**
 * @brief Unregister Fileevent NPI providers.
 *
 */
void
ebpf_ext_unregister_fileevent();

/**
 * @brief Register Fileevent NPI providers.
 *
 * @retval STATUS_SUCCESS Operation succeeded.
 * @retval STATUS_UNSUCCESSFUL Operation failed.
 */
NTSTATUS
ebpf_ext_register_fileevent();
