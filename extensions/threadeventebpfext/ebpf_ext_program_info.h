#pragma once

#include "ebpf_ext.h"
#include "ebpf_extension.h"
#include "ebpf_ntos_hooks.h"
#include "ebpf_ntos_program_attach_type_guids.h"
#include "ebpf_program_types.h"

// Thread program information.
static const ebpf_helper_function_prototype_t _thread_ebpf_extension_helper_function_prototype[] = {
    {.header = {EBPF_HELPER_FUNCTION_PROTOTYPE_CURRENT_VERSION, EBPF_HELPER_FUNCTION_PROTOTYPE_CURRENT_VERSION_SIZE},
     .helper_id = EBPF_MAX_GENERAL_HELPER_FUNCTION + 1,
     .name = "bpf_thread_get_image_path",
     .return_type = EBPF_RETURN_TYPE_INTEGER,
     .arguments =
         {EBPF_ARGUMENT_TYPE_PTR_TO_CTX, EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM, EBPF_ARGUMENT_TYPE_CONST_SIZE}},
};

static const ebpf_context_descriptor_t _ebpf_thread_context_descriptor = {
    sizeof(thread_md_t),
    -1, // No data start offset for thread context
    -1, // No data end offset for thread context
    -1,
};

// Need to allocate these in ebpf_structs.h in ebpf-for-windows repo.
#define BPF_PROG_TYPE_THREAD 99931
#define BPF_ATTACH_TYPE_THREAD 99931

static const ebpf_program_type_descriptor_t _ebpf_thread_program_type_descriptor = {
    .header = {EBPF_PROGRAM_TYPE_DESCRIPTOR_CURRENT_VERSION, EBPF_PROGRAM_TYPE_DESCRIPTOR_CURRENT_VERSION_SIZE},
    .name = "thread",
    .context_descriptor = &_ebpf_thread_context_descriptor,
    .program_type = EBPF_PROGRAM_TYPE_THREAD_GUID,
    .bpf_prog_type = BPF_PROG_TYPE_THREAD,
};

static const ebpf_program_info_t _ebpf_thread_program_info = {
    .header = {EBPF_PROGRAM_INFORMATION_CURRENT_VERSION, EBPF_PROGRAM_INFORMATION_CURRENT_VERSION_SIZE},
    .program_type_descriptor = &_ebpf_thread_program_type_descriptor,
    .count_of_program_type_specific_helpers = EBPF_COUNT_OF(_thread_ebpf_extension_helper_function_prototype),
    .program_type_specific_helper_prototype = _thread_ebpf_extension_helper_function_prototype,
};

static const ebpf_program_section_info_t _ebpf_thread_section_info[] = {
    {
        .header =
            {EBPF_PROGRAM_SECTION_INFORMATION_CURRENT_VERSION, EBPF_PROGRAM_SECTION_INFORMATION_CURRENT_VERSION_SIZE},
        .section_name = (wchar_t*)L"thread",
        .program_type = &EBPF_PROGRAM_TYPE_THREAD,
        .attach_type = &EBPF_ATTACH_TYPE_THREAD,
        .bpf_program_type = BPF_PROG_TYPE_THREAD,
        .bpf_attach_type = BPF_ATTACH_TYPE_THREAD,
    },
};