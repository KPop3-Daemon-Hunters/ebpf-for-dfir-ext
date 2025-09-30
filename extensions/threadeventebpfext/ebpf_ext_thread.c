#include "ebpf_ntos_hooks.h"
#include "ebpf_ext_thread.h"
#include "ebpf_ext_program_info.h"

#include <errno.h>

static ebpf_result_t
_ebpf_thread_context_create(
    _In_reads_bytes_opt_(data_size_in) const uint8_t* data_in,
    size_t data_size_in,
    _In_reads_bytes_opt_(context_size_in) const uint8_t* context_in,
    size_t context_size_in,
    _Outptr_ void** context);

static void
_ebpf_thread_context_destroy(
    _In_opt_ void* context,
    _Out_writes_bytes_to_(*data_size_out, *data_size_out) uint8_t* data_out,
    _Inout_ size_t* data_size_out,
    _Out_writes_bytes_to_(*context_size_out, *context_size_out) uint8_t* context_out,
    _Inout_ size_t* context_size_out);

void
_ebpf_thread_create_thread_notify_routine_ex(
    _In_ HANDLE process_id, _In_ HANDLE thread_id, _In_ BOOLEAN create);

_Success_(return >= 0) static int32_t _ebpf_thread_get_image_path(
    _In_ thread_md_t* thread_md, _Out_writes_bytes_(path_length) uint8_t* path, uint32_t path_length);

static const void* _ebpf_thread_helper_functions[] = {(void*)&_ebpf_thread_get_image_path};

#define Log(format, ...) DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[KernelThread]" format "\n", ##__VA_ARGS__)


static ebpf_helper_function_addresses_t _ebpf_thread_helper_function_address_table = {
    .header = {EBPF_HELPER_FUNCTION_ADDRESSES_CURRENT_VERSION, EBPF_HELPER_FUNCTION_ADDRESSES_CURRENT_VERSION_SIZE},
    .helper_function_count = EBPF_COUNT_OF(_ebpf_thread_helper_functions),
    .helper_function_address = (uint64_t*)_ebpf_thread_helper_functions,
};

//
// Thread Program Information NPI Provider.
//
static ebpf_program_data_t _ebpf_thread_program_data = {
    .header = EBPF_PROGRAM_DATA_HEADER,
    .program_info = &_ebpf_thread_program_info,
    .program_type_specific_helper_function_addresses = &_ebpf_thread_helper_function_address_table,
    .context_create = _ebpf_thread_context_create,
    .context_destroy = _ebpf_thread_context_destroy,
    .required_irql = PASSIVE_LEVEL,
    .capabilities = {.supports_context_header = true},
};

static ebpf_extension_data_t _ebpf_thread_program_info_provider_data = {
    .header = {EBPF_EXTENSION_NPI_PROVIDER_VERSION, sizeof(_ebpf_thread_program_data)},
    .data = &_ebpf_thread_program_data};

NPI_MODULEID DECLSPEC_SELECTANY _ebpf_thread_program_info_provider_moduleid = {sizeof(NPI_MODULEID), MIT_GUID, {0}};

static ebpf_extension_program_info_provider_t* _ebpf_thread_program_info_provider_context = NULL;

//
// Thread Hook NPI Provider.
//
ebpf_attach_provider_data_t _ntos_ebpf_thread_hook_provider_data = {
    .header = {EBPF_ATTACH_PROVIDER_DATA_CURRENT_VERSION, EBPF_ATTACH_PROVIDER_DATA_CURRENT_VERSION_SIZE},
    .supported_program_type = EBPF_PROGRAM_TYPE_THREAD_GUID,
    .bpf_attach_type = (bpf_attach_type_t)BPF_ATTACH_TYPE_THREAD,
};

NPI_MODULEID DECLSPEC_SELECTANY _ebpf_thread_hook_provider_moduleid = {sizeof(NPI_MODULEID), MIT_GUID, {0}};

static ebpf_extension_hook_provider_t* _ebpf_thread_hook_provider_context = NULL;

EX_PUSH_LOCK _ebpf_thread_hook_provider_lock;
bool _ebpf_thread_hook_provider_registered = FALSE;
uint64_t _ebpf_thread_hook_provider_registration_count = 0;


//
// Client attach/detach handler routines.
//

static ebpf_result_t
_ntos_ebpf_extension_thread_on_client_attach(
    _In_ const ebpf_extension_hook_client_t* attaching_client,
    _In_ const ebpf_extension_hook_provider_t* provider_context)
{
    ebpf_result_t result = EBPF_SUCCESS;
    bool push_lock_acquired = false;

    EBPF_EXT_LOG_ENTRY();

    UNREFERENCED_PARAMETER(attaching_client);
    UNREFERENCED_PARAMETER(provider_context);

    ExAcquirePushLockExclusive(&_ebpf_thread_hook_provider_lock);

    push_lock_acquired = true;

    if (!_ebpf_thread_hook_provider_registered) {
        // Register the thread create notify routine.
        NTSTATUS status = PsSetCreateThreadNotifyRoutineEx(PsCreateThreadNotifyNonSystem, (PVOID)_ebpf_thread_create_thread_notify_routine_ex);
        if (!NT_SUCCESS(status)) {
            EBPF_EXT_LOG_MESSAGE_NTSTATUS(
                EBPF_EXT_TRACELOG_LEVEL_ERROR,
                EBPF_EXT_TRACELOG_KEYWORD_BASE,
                "PsSetCreateThreadNotifyRoutineEx failed",
                status);
            result = EBPF_OPERATION_NOT_SUPPORTED;
            goto Exit;
        }
        _ebpf_thread_hook_provider_registered = TRUE;
    }

    _ebpf_thread_hook_provider_registration_count++;

Exit:
    if (push_lock_acquired) {
        ExReleasePushLockExclusive(&_ebpf_thread_hook_provider_lock);
    }

    EBPF_EXT_RETURN_RESULT(result);
}

static void
_ntos_ebpf_extension_thread_on_client_detach(_In_ const ebpf_extension_hook_client_t* detaching_client)
{
    ebpf_result_t result = EBPF_SUCCESS;

    EBPF_EXT_LOG_ENTRY();

    UNREFERENCED_PARAMETER(detaching_client);

    // Unregister the thread create notify routine.
    ExAcquirePushLockExclusive(&_ebpf_thread_hook_provider_lock);

    _ebpf_thread_hook_provider_registration_count--;

    if (_ebpf_thread_hook_provider_registered && _ebpf_thread_hook_provider_registration_count == 0) {
        NTSTATUS status = PsRemoveCreateThreadNotifyRoutine(_ebpf_thread_create_thread_notify_routine_ex);
        if (!NT_SUCCESS(status)) {
            EBPF_EXT_LOG_MESSAGE_NTSTATUS(
                EBPF_EXT_TRACELOG_LEVEL_ERROR,
                EBPF_EXT_TRACELOG_KEYWORD_BASE,
                "PsRemoveCreateThreadNotifyRoutine failed",
                status);
            result = EBPF_OPERATION_NOT_SUPPORTED;
        }
        _ebpf_thread_hook_provider_registered = FALSE;
    }

    ExReleasePushLockExclusive(&_ebpf_thread_hook_provider_lock);

    EBPF_EXT_LOG_EXIT();
}

//
// NMR Registration Helper Routines.
//

void
ebpf_ext_unregister_ntos()
{
    if (_ebpf_thread_hook_provider_context) {
        ebpf_extension_hook_provider_unregister(_ebpf_thread_hook_provider_context);
        _ebpf_thread_hook_provider_context = NULL;
    }
    if (_ebpf_thread_program_info_provider_context) {
        ebpf_extension_program_info_provider_unregister(_ebpf_thread_program_info_provider_context);
        _ebpf_thread_program_info_provider_context = NULL;
    }
}

NTSTATUS
ebpf_ext_register_ntos()
{
    NTSTATUS status = STATUS_SUCCESS;

    EBPF_EXT_LOG_ENTRY();

    const ebpf_extension_program_info_provider_parameters_t program_info_provider_parameters = {
        &_ebpf_thread_program_info_provider_moduleid, &_ebpf_thread_program_data};
    const ebpf_extension_hook_provider_parameters_t hook_provider_parameters = {
        &_ebpf_thread_hook_provider_moduleid, &_ntos_ebpf_thread_hook_provider_data};

    // Set the program type as the provider module id.
    _ebpf_thread_program_info_provider_moduleid.Guid = EBPF_PROGRAM_TYPE_THREAD;
    _ebpf_thread_hook_provider_moduleid.Guid = EBPF_ATTACH_TYPE_THREAD;
    status = ebpf_extension_program_info_provider_register(
        &program_info_provider_parameters, &_ebpf_thread_program_info_provider_context);
    if (!NT_SUCCESS(status)) {
        EBPF_EXT_LOG_MESSAGE_NTSTATUS(
            EBPF_EXT_TRACELOG_LEVEL_ERROR,
            EBPF_EXT_TRACELOG_KEYWORD_BASE,
            "ebpf_extension_program_info_provider_register",
            status);
        goto Exit;
    }

    status = ebpf_extension_hook_provider_register(
        &hook_provider_parameters,
        _ntos_ebpf_extension_thread_on_client_attach,
        _ntos_ebpf_extension_thread_on_client_detach,
        NULL,
        &_ebpf_thread_hook_provider_context);
    if (status != EBPF_SUCCESS) {
        EBPF_EXT_LOG_MESSAGE_NTSTATUS(
            EBPF_EXT_TRACELOG_LEVEL_ERROR,
            EBPF_EXT_TRACELOG_KEYWORD_BASE,
            "ebpf_extension_hook_provider_register",
            status);
        goto Exit;
    }

Exit:
    if (!NT_SUCCESS(status)) {
        ebpf_ext_unregister_ntos();
    }
    EBPF_EXT_RETURN_NTSTATUS(status);
}

typedef struct _thread_notify_context
{
    EBPF_CONTEXT_HEADER;
    thread_md_t thread_md;
    HANDLE process_id;
    HANDLE thread_id;
    BOOLEAN create;
} thread_notify_context_t;

static ebpf_result_t
_ebpf_thread_context_create(
    _In_reads_bytes_opt_(data_size_in) const uint8_t* data_in,
    size_t data_size_in,
    _In_reads_bytes_opt_(context_size_in) const uint8_t* context_in,
    size_t context_size_in,
    _Outptr_ void** context)
{
    EBPF_EXT_LOG_ENTRY();
    ebpf_result_t result;
    thread_notify_context_t* thread_context = NULL;

    *context = NULL;

    // 참조되지 않은 매개변수 경고(C4100) 방지
    UNREFERENCED_PARAMETER(data_in);
    UNREFERENCED_PARAMETER(data_size_in);

    if (context_in == NULL || context_size_in < sizeof(thread_md_t)) {
        EBPF_EXT_LOG_MESSAGE(EBPF_EXT_TRACELOG_LEVEL_ERROR, EBPF_EXT_TRACELOG_KEYWORD_BASE, "Context is required");
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    thread_context = (thread_notify_context_t*)ExAllocatePoolUninitialized(
        NonPagedPoolNx, sizeof(thread_notify_context_t), EBPF_EXTENSION_POOL_TAG);
    EBPF_EXT_BAIL_ON_ALLOC_FAILURE_RESULT(
        EBPF_EXT_TRACELOG_KEYWORD_BASE, thread_context, "thread_context", result);

    // Copy the context from the caller.
    memcpy(thread_context, context_in, sizeof(thread_md_t));

    *context = thread_context;
    thread_context = NULL;
    result = EBPF_SUCCESS;

Exit:
    if (thread_context) {
        ExFreePool(thread_context);
        thread_context = NULL;
    }
    EBPF_EXT_RETURN_RESULT(result);
}

static void
_ebpf_thread_context_destroy(
    _In_opt_ void* context,
    _Out_writes_bytes_to_(*data_size_out, *data_size_out) uint8_t* data_out,
    _Inout_ size_t* data_size_out,
    _Out_writes_bytes_to_(*context_size_out, *context_size_out) uint8_t* context_out,
    _Inout_ size_t* context_size_out)
{
    EBPF_EXT_LOG_ENTRY();

	UNREFERENCED_PARAMETER(data_out);

    thread_notify_context_t* thread_context = (thread_notify_context_t*)context;
    thread_md_t* thread_context_out = (thread_md_t*)context_out;

    if (!thread_context) {
        goto Exit;
    }

    if (context_out != NULL && *context_size_out >= sizeof(thread_md_t)) {
        // Copy the context to the caller.
        memcpy(thread_context_out, &thread_context->thread_md, sizeof(thread_md_t));
        *context_size_out = sizeof(thread_md_t);
    } else {
        *context_size_out = 0;
    }

    // No data to copy for threads
    *data_size_out = 0;

    ExFreePool(thread_context);

Exit:
    EBPF_EXT_LOG_EXIT();
}

void
_ebpf_thread_create_thread_notify_routine_ex(
    _In_ HANDLE process_id, _In_ HANDLE thread_id, _In_ BOOLEAN create)
{
    thread_notify_context_t thread_notify_context = {
        .thread_md = {0}, .process_id = process_id, .thread_id = thread_id, .create = create};

    EBPF_EXT_LOG_ENTRY();
    ebpf_extension_hook_client_t* client_context;

    thread_notify_context.thread_md.thread_id = (uint64_t)thread_id;
    thread_notify_context.thread_md.process_id = (uint64_t)process_id;
    thread_notify_context.thread_md.creating_process_id = (uint64_t)PsGetCurrentProcessId();
    thread_notify_context.thread_md.creating_thread_id = (uint64_t)PsGetCurrentThreadId();

    // Get current time
    LARGE_INTEGER current_time;
    KeQuerySystemTime(&current_time);
    thread_notify_context.thread_md.creation_time = current_time.QuadPart;

    if (create) {
        thread_notify_context.thread_md.operation = THREAD_OPERATION_CREATE;
    } else {
        thread_notify_context.thread_md.operation = THREAD_OPERATION_DELETE;
        thread_notify_context.thread_md.exit_time = current_time.QuadPart;
        thread_notify_context.thread_md.thread_exit_code = 0; // Exit code not available in this callback
    }

    // For each attached client call the thread hook.
    ebpf_result_t result;
    client_context = ebpf_extension_hook_get_next_attached_client(_ebpf_thread_hook_provider_context, NULL);
    while (client_context != NULL) {
        NTSTATUS status = 0;
        if (ebpf_extension_hook_client_enter_rundown(client_context)) {
            result = ebpf_extension_hook_invoke_program(
                client_context, &thread_notify_context.thread_md, (uint32_t*)&status);
            if (result != EBPF_SUCCESS) {
                EBPF_EXT_LOG_MESSAGE(
                    EBPF_EXT_TRACELOG_LEVEL_ERROR,
                    EBPF_EXT_TRACELOG_KEYWORD_BASE,
                    "ebpf_extension_hook_invoke_program failed");
            }
            ebpf_extension_hook_client_leave_rundown(client_context);
        } else {
            EBPF_EXT_LOG_MESSAGE(
                EBPF_EXT_TRACELOG_LEVEL_ERROR,
                EBPF_EXT_TRACELOG_KEYWORD_BASE,
                "ebpf_extension_hook_client_enter_rundown failed");
        }

        client_context =
            ebpf_extension_hook_get_next_attached_client(_ebpf_thread_hook_provider_context, client_context);
    }

    EBPF_EXT_LOG_EXIT();
}

_Success_(return >= 0) static int32_t _ebpf_thread_get_image_path(
    _In_ thread_md_t* thread_md, _Out_writes_bytes_(path_length) uint8_t* path, uint32_t path_length)
{
    CONTAINING_RECORD(thread_md, thread_notify_context_t, thread_md);

    
    int32_t result = 0;

    // For thread events, we can try to get the image path of the owning process
    PEPROCESS process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)thread_md->process_id, &process);
    if (NT_SUCCESS(status) && process != NULL) {
        // Try to get the image file name
        PUNICODE_STRING image_name = NULL;
        status = SeLocateProcessImageName(process, &image_name);
        if (NT_SUCCESS(status) && image_name != NULL && image_name->Buffer != NULL) {
            if (path_length >= image_name->Length) {
                memcpy(path, image_name->Buffer, image_name->Length);
                result = image_name->Length;
            }
            ExFreePool(image_name);
        }
        ObDereferenceObject(process);
    }

    return result;
}