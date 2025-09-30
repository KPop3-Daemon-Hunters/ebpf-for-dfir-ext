// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once
#include <stdint.h>

// This file contains APIs for hooks and helpers that are
// exposed by ntosebpfext.sys for use by eBPF programs.

typedef enum _process_operation
{
    PROCESS_OPERATION_CREATE, ///< Process creation.
    PROCESS_OPERATION_DELETE, ///< Process deletion.
} process_operation_t;

typedef enum _file_operation
{
    FILE_OPERATION_READ,
    FILE_OPERATION_WRITE
} file_operation_t;

typedef struct _process_md
{
    uint8_t* command_start;            ///< Pointer to start of the command line as UTF-16 string.
    uint8_t* command_end;              ///< Pointer to end of the command line as UTF-16 string.
    uint64_t process_id;               ///< Process ID.
    uint64_t parent_process_id;        ///< Parent process ID.
    uint64_t creating_process_id;      ///< Creating process ID.
    uint64_t creating_thread_id;       ///< Creating thread ID.
    uint64_t creation_time;            ///< Process creation time (as a FILETIME).
    uint64_t exit_time;                ///< Process exit time (as a FILETIME).  Set only for PROCESS_OPERATION_DELETE.
    uint32_t process_exit_code;        ///< Process exit status.  Set only for PROCESS_OPERATION_DELETE.
    process_operation_t operation : 8; ///< Operation to do.
} process_md_t;

typedef struct _file_event_md
{
    file_operation_t operation : 8;
    // TBD;
} file_event_md_t;

/*
 * @brief Handle process creation and deletion.
 *
 * Program type: \ref EBPF_PROGRAM_TYPE_PROCESS
 *
 * Attach type(s):
 * \ref EBPF_ATTACH_TYPE_PROCESS
 *
 * @param[in] context \ref process_md_t
 * @return STATUS_SUCCESS to permit the operation, or a failure NTSTATUS value to deny the operation.
 * Value of STATUS_SUCCESS is 0x0.
 * For PROCESS_OPERATION_DELETE operation, the return value is ignored.
 */
typedef int
process_hook_t(process_md_t* context);

// Process helper functions.
#define PROCESS_EXT_HELPER_FN_BASE 0xFFFF

#if !defined(__doxygen) && !defined(EBPF_HELPER)
#define EBPF_HELPER(return_type, name, args) typedef return_type(*name##_t) args
#endif

typedef enum
{
    BPF_FUNC_process_get_image_path = PROCESS_EXT_HELPER_FN_BASE + 1,
} ebpf_process_helper_id_t;

/**
 * @brief Get the image path of the process.
 *
 * @param[in] context Process metadata.
 * @param[out] path Buffer to store the image path.
 * @param[in] path_length Length of the buffer.
 *
 * @retval >=0 The length of the image path.
 * @retval <0 A failure occurred.
 */
EBPF_HELPER(int, bpf_process_get_image_path, (process_md_t * ctx, uint8_t* path, uint32_t path_length));
#ifndef __doxygen
#define bpf_process_get_image_path ((bpf_process_get_image_path_t)BPF_FUNC_process_get_image_path)
#endif

// Thread event types and structures
typedef enum _thread_operation
{
    THREAD_OPERATION_CREATE, ///< Thread creation.
    THREAD_OPERATION_DELETE, ///< Thread deletion.
} thread_operation_t;

typedef struct _thread_md
{
    uint64_t thread_id;                ///< Thread ID.
    uint64_t process_id;               ///< Process ID that owns the thread.
    uint64_t creating_process_id;      ///< Creating process ID.
    uint64_t creating_thread_id;       ///< Creating thread ID.
    uint64_t creation_time;            ///< Thread creation time (as a FILETIME).
    uint64_t exit_time;                ///< Thread exit time (as a FILETIME). Set only for THREAD_OPERATION_DELETE.
    uint32_t thread_exit_code;         ///< Thread exit code. Set only for THREAD_OPERATION_DELETE.
    thread_operation_t operation : 8;  ///< Operation to do.
} thread_md_t;

// Thread helper functions.
#define THREAD_EXT_HELPER_FN_BASE 0xFFFE

typedef enum
{
    BPF_FUNC_thread_get_image_path = THREAD_EXT_HELPER_FN_BASE + 1,
} ebpf_thread_helper_id_t;

/**
 * @brief Get the image path of the process that owns the thread.
 *
 * @param[in] context Thread metadata.
 * @param[out] path Buffer to store the image path.
 * @param[in] path_length Length of the buffer.
 *
 * @retval >=0 The length of the image path.
 * @retval <0 A failure occurred.
 */
EBPF_HELPER(int, bpf_thread_get_image_path, (thread_md_t * ctx, uint8_t* path, uint32_t path_length));
#ifndef __doxygen
#define bpf_thread_get_image_path ((bpf_thread_get_image_path_t)BPF_FUNC_thread_get_image_path)
#endif

// Object event types and structures
typedef enum _object_operation
{
    OBJECT_OPERATION_HANDLE_CREATE,     ///< Handle creation (pre-operation).
    OBJECT_OPERATION_HANDLE_DUPLICATE,  ///< Handle duplication (pre-operation).
} object_operation_t;

typedef enum _object_type
{
    OBJECT_TYPE_PROCESS,  ///< Process object.
    OBJECT_TYPE_THREAD,   ///< Thread object.
} object_type_t;

typedef struct _object_md
{
    uint64_t object_pointer;           ///< Pointer to the object (PEPROCESS or PETHREAD).
    uint64_t source_process_id;        ///< Process ID that is opening the handle.
    uint64_t source_thread_id;         ///< Thread ID that is opening the handle.
    uint64_t target_process_id;        ///< Target process ID (for process objects) or owning process ID (for thread objects).
    uint64_t target_thread_id;         ///< Target thread ID (only for thread objects, 0 otherwise).
    uint32_t desired_access;           ///< Desired access mask for the handle.
    uint32_t original_desired_access;  ///< Original desired access before any modifications.
    object_type_t object_type : 8;     ///< Type of object.
    object_operation_t operation : 8;  ///< Operation being performed.
} object_md_t;

/*
 * @brief Handle object operations (process/thread handle open).
 *
 * Program type: \ref EBPF_PROGRAM_TYPE_OBJECT
 *
 * Attach type(s):
 * \ref EBPF_ATTACH_TYPE_OBJECT
 *
 * @param[in] context \ref object_md_t
 * @return STATUS_SUCCESS to permit the operation, or a failure NTSTATUS value to deny/modify the operation.
 * The desired_access field in context can be modified to filter out specific access rights.
 */
typedef int
object_hook_t(object_md_t* context);

// Object helper functions.
#define OBJECT_EXT_HELPER_FN_BASE 0xFFFD

typedef enum
{
    BPF_FUNC_object_get_image_path = OBJECT_EXT_HELPER_FN_BASE + 1,
} ebpf_object_helper_id_t;

/**
 * @brief Get the image path of the target process.
 *
 * @param[in] context Object metadata.
 * @param[out] path Buffer to store the image path.
 * @param[in] path_length Length of the buffer.
 *
 * @retval >=0 The length of the image path.
 * @retval <0 A failure occurred.
 */
EBPF_HELPER(int, bpf_object_get_image_path, (object_md_t * ctx, uint8_t* path, uint32_t path_length));
#ifndef __doxygen
#define bpf_object_get_image_path ((bpf_object_get_image_path_t)BPF_FUNC_object_get_image_path)
#endif
