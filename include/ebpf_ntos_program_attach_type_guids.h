// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf_windows.h"

#ifdef __cplusplus
extern "C"
{
#endif
    //
    // Attach Types.
    //

    /** @brief Attach type for handling process creation and destruction events.
     *
     * Program type: \ref EBPF_ATTACH_TYPE_PROCESS
     */
    __declspec(selectany) ebpf_attach_type_t EBPF_ATTACH_TYPE_PROCESS = {
        0x66e20687, 0x9805, 0x4458, {0xa0, 0xdb, 0x38, 0xe2, 0x20, 0xd3, 0x16, 0x85}};

    //
    // Program Types.
    //

#define EBPF_PROGRAM_TYPE_PROCESS_GUID                                                 \
    {                                                                                  \
        0x22ea7b37, 0x1043, 0x4d0d, { 0xb6, 0x0d, 0xca, 0xfa, 0x1c, 0x7b, 0x63, 0x8e } \
    }

    /** @brief Program type for handling process creation and destruction events.
     *
     * eBPF program prototype: \ref process_md_t
     *
     * Attach type(s): \ref EBPF_ATTACH_TYPE_PRCOESS
     *
     * Helpers available: see bpf_helpers.h
     */
    __declspec(selectany) ebpf_program_type_t EBPF_PROGRAM_TYPE_PROCESS = EBPF_PROGRAM_TYPE_PROCESS_GUID;

    /** @brief Attach type for handling thread creation and destruction events.
     *
     * Program type: \ref EBPF_ATTACH_TYPE_THREAD
     */
    __declspec(selectany) ebpf_attach_type_t EBPF_ATTACH_TYPE_THREAD = {
        0x87f6a8f3, 0x9c41, 0x4e5d, {0xa9, 0x3e, 0xf1, 0x77, 0x8b, 0xcd, 0x45, 0x21}};

#define EBPF_PROGRAM_TYPE_THREAD_GUID                                                  \
    {                                                                                  \
        0x9a3b8f7e, 0x6d42, 0x4b8c, { 0xb7, 0x5f, 0xde, 0x9a, 0x8c, 0x7f, 0x34, 0xa2 } \
    }

    /** @brief Program type for handling thread creation and destruction events.
     *
     * eBPF program prototype: \ref thread_md_t
     *
     * Attach type(s): \ref EBPF_ATTACH_TYPE_THREAD
     *
     * Helpers available: see bpf_helpers.h
     */
    __declspec(selectany) ebpf_program_type_t EBPF_PROGRAM_TYPE_THREAD = EBPF_PROGRAM_TYPE_THREAD_GUID;

    /** @brief Attach type for handling object (process/thread) handle operations.
     *
     * Program type: \ref EBPF_ATTACH_TYPE_OBJECT
     */
    __declspec(selectany) ebpf_attach_type_t EBPF_ATTACH_TYPE_OBJECT = {
        0xb5e9d6c4, 0x7a81, 0x4f3e, {0xbc, 0x4a, 0xf2, 0x88, 0x9d, 0xef, 0x67, 0x89}};

#define EBPF_PROGRAM_TYPE_OBJECT_GUID                                                  \
    {                                                                                  \
        0xc7f3e9a2, 0x8d64, 0x4c9f, { 0xa5, 0x6b, 0xcd, 0x8e, 0x7f, 0xa9, 0x45, 0xb3 } \
    }

    /** @brief Program type for handling object (process/thread) handle operations.
     *
     * eBPF program prototype: \ref object_md_t
     *
     * Attach type(s): \ref EBPF_ATTACH_TYPE_OBJECT
     *
     * Helpers available: see bpf_helpers.h
     */
    __declspec(selectany) ebpf_program_type_t EBPF_PROGRAM_TYPE_OBJECT = EBPF_PROGRAM_TYPE_OBJECT_GUID;

#ifdef __cplusplus
}
#endif
