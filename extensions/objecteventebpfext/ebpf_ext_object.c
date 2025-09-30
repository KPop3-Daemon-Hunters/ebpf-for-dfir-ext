#include "ebpf_ntos_hooks.h"
#include "ebpf_ext_object.h"
#include "ebpf_ext_program_info.h"

#include <errno.h>

static ebpf_result_t
_ebpf_object_context_create(
    _In_reads_bytes_opt_(data_size_in) const uint8_t* data_in,
    size_t data_size_in,
    _In_reads_bytes_opt_(context_size_in) const uint8_t* context_in,
    size_t context_size_in,
    _Outptr_ void** context);

static void
_ebpf_object_context_destroy(
    _In_opt_ void* context,
    _Out_writes_bytes_to_(*data_size_out, *data_size_out) uint8_t* data_out,
    _Inout_ size_t* data_size_out,
    _Out_writes_bytes_to_(*context_size_out, *context_size_out) uint8_t* context_out,
    _Inout_ size_t* context_size_out);

OB_PREOP_CALLBACK_STATUS
_ebpf_object_pre_operation_callback(
    _In_ PVOID registration_context,
    _In_ POB_PRE_OPERATION_INFORMATION operation_information);

_Success_(return >= 0) static int32_t _ebpf_object_get_image_path(
    _In_ object_md_t* object_md, _Out_writes_bytes_(path_length) uint8_t* path, uint32_t path_length);

static const void* _ebpf_object_helper_functions[] = {(void*)&_ebpf_object_get_image_path};

#define Log(format, ...) DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[KernelObject]" format "\n", ##__VA_ARGS__)


static ebpf_helper_function_addresses_t _ebpf_object_helper_function_address_table = {
    .header = {EBPF_HELPER_FUNCTION_ADDRESSES_CURRENT_VERSION, EBPF_HELPER_FUNCTION_ADDRESSES_CURRENT_VERSION_SIZE},
    .helper_function_count = EBPF_COUNT_OF(_ebpf_object_helper_functions),
    .helper_function_address = (uint64_t*)_ebpf_object_helper_functions,
};

//
// Object Program Information NPI Provider.
//
static ebpf_program_data_t _ebpf_object_program_data = {
    .header = EBPF_PROGRAM_DATA_HEADER,
    .program_info = &_ebpf_object_program_info,
    .program_type_specific_helper_function_addresses = &_ebpf_object_helper_function_address_table,
    .context_create = _ebpf_object_context_create,
    .context_destroy = _ebpf_object_context_destroy,
    .required_irql = PASSIVE_LEVEL,
    .capabilities = {.supports_context_header = true},
};

static ebpf_extension_data_t _ebpf_object_program_info_provider_data = {
    .header = {EBPF_EXTENSION_NPI_PROVIDER_VERSION, sizeof(_ebpf_object_program_data)},
    .data = &_ebpf_object_program_data};

NPI_MODULEID DECLSPEC_SELECTANY _ebpf_object_program_info_provider_moduleid = {sizeof(NPI_MODULEID), MIT_GUID, {0}};

static ebpf_extension_program_info_provider_t* _ebpf_object_program_info_provider_context = NULL;

//
// Object Hook NPI Provider.
//
ebpf_attach_provider_data_t _ntos_ebpf_object_hook_provider_data = {
    .header = {EBPF_ATTACH_PROVIDER_DATA_CURRENT_VERSION, EBPF_ATTACH_PROVIDER_DATA_CURRENT_VERSION_SIZE},
    .supported_program_type = EBPF_PROGRAM_TYPE_OBJECT_GUID,
    .bpf_attach_type = (bpf_attach_type_t)BPF_ATTACH_TYPE_OBJECT,
};

NPI_MODULEID DECLSPEC_SELECTANY _ebpf_object_hook_provider_moduleid = {sizeof(NPI_MODULEID), MIT_GUID, {0}};

static ebpf_extension_hook_provider_t* _ebpf_object_hook_provider_context = NULL;

EX_PUSH_LOCK _ebpf_object_hook_provider_lock;
bool _ebpf_object_hook_provider_registered = FALSE;
uint64_t _ebpf_object_hook_provider_registration_count = 0;

// ObRegisterCallbacks registration handle
PVOID _ebpf_object_callback_registration = NULL;


//
// Client attach/detach handler routines.
//

static ebpf_result_t
_ntos_ebpf_extension_object_on_client_attach(
    _In_ const ebpf_extension_hook_client_t* attaching_client,
    _In_ const ebpf_extension_hook_provider_t* provider_context)
{
    ebpf_result_t result = EBPF_SUCCESS;
    bool push_lock_acquired = false;

    EBPF_EXT_LOG_ENTRY();

    UNREFERENCED_PARAMETER(attaching_client);
    UNREFERENCED_PARAMETER(provider_context);

    ExAcquirePushLockExclusive(&_ebpf_object_hook_provider_lock);

    push_lock_acquired = true;

    if (!_ebpf_object_hook_provider_registered) {
        // Register ObRegisterCallbacks for process and thread handle operations
        OB_CALLBACK_REGISTRATION callback_registration;
        OB_OPERATION_REGISTRATION operation_registrations[2];

        // Process callback registration
        operation_registrations[0].ObjectType = PsProcessType;
        operation_registrations[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
        operation_registrations[0].PreOperation = _ebpf_object_pre_operation_callback;
        operation_registrations[0].PostOperation = NULL;

        // Thread callback registration
        operation_registrations[1].ObjectType = PsThreadType;
        operation_registrations[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
        operation_registrations[1].PreOperation = _ebpf_object_pre_operation_callback;
        operation_registrations[1].PostOperation = NULL;

        UNICODE_STRING altitude;
        RtlInitUnicodeString(&altitude, L"385200"); // Altitude for eBPF object callback

        callback_registration.Version = OB_FLT_REGISTRATION_VERSION;
        callback_registration.OperationRegistrationCount = 2;
        callback_registration.Altitude = altitude;
        callback_registration.RegistrationContext = NULL;
        callback_registration.OperationRegistration = operation_registrations;

        NTSTATUS status = ObRegisterCallbacks(&callback_registration, &_ebpf_object_callback_registration);
        if (!NT_SUCCESS(status)) {
            EBPF_EXT_LOG_MESSAGE_NTSTATUS(
                EBPF_EXT_TRACELOG_LEVEL_ERROR,
                EBPF_EXT_TRACELOG_KEYWORD_BASE,
                "ObRegisterCallbacks failed",
                status);
            result = EBPF_OPERATION_NOT_SUPPORTED;
            goto Exit;
        }
        _ebpf_object_hook_provider_registered = TRUE;
    }

    _ebpf_object_hook_provider_registration_count++;

Exit:
    if (push_lock_acquired) {
        ExReleasePushLockExclusive(&_ebpf_object_hook_provider_lock);
    }

    EBPF_EXT_RETURN_RESULT(result);
}

static void
_ntos_ebpf_extension_object_on_client_detach(_In_ const ebpf_extension_hook_client_t* detaching_client)
{
    EBPF_EXT_LOG_ENTRY();

    UNREFERENCED_PARAMETER(detaching_client);

    // Unregister the object callback.
    ExAcquirePushLockExclusive(&_ebpf_object_hook_provider_lock);

    _ebpf_object_hook_provider_registration_count--;

    if (_ebpf_object_hook_provider_registered && _ebpf_object_hook_provider_registration_count == 0) {
        if (_ebpf_object_callback_registration != NULL) {
            ObUnRegisterCallbacks(_ebpf_object_callback_registration);
            _ebpf_object_callback_registration = NULL;
        }
        _ebpf_object_hook_provider_registered = FALSE;
    }

    ExReleasePushLockExclusive(&_ebpf_object_hook_provider_lock);

    EBPF_EXT_LOG_EXIT();
}

//
// NMR Registration Helper Routines.
//

void
ebpf_ext_unregister_ntos()
{
    if (_ebpf_object_hook_provider_context) {
        ebpf_extension_hook_provider_unregister(_ebpf_object_hook_provider_context);
        _ebpf_object_hook_provider_context = NULL;
    }
    if (_ebpf_object_program_info_provider_context) {
        ebpf_extension_program_info_provider_unregister(_ebpf_object_program_info_provider_context);
        _ebpf_object_program_info_provider_context = NULL;
    }
}

NTSTATUS
ebpf_ext_register_ntos()
{
    NTSTATUS status = STATUS_SUCCESS;

    EBPF_EXT_LOG_ENTRY();

    const ebpf_extension_program_info_provider_parameters_t program_info_provider_parameters = {
        &_ebpf_object_program_info_provider_moduleid, &_ebpf_object_program_data};
    const ebpf_extension_hook_provider_parameters_t hook_provider_parameters = {
        &_ebpf_object_hook_provider_moduleid, &_ntos_ebpf_object_hook_provider_data};

    // Set the program type as the provider module id.
    _ebpf_object_program_info_provider_moduleid.Guid = EBPF_PROGRAM_TYPE_OBJECT;
    _ebpf_object_hook_provider_moduleid.Guid = EBPF_ATTACH_TYPE_OBJECT;
    status = ebpf_extension_program_info_provider_register(
        &program_info_provider_parameters, &_ebpf_object_program_info_provider_context);
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
        _ntos_ebpf_extension_object_on_client_attach,
        _ntos_ebpf_extension_object_on_client_detach,
        NULL,
        &_ebpf_object_hook_provider_context);
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

typedef struct _object_callback_context
{
    EBPF_CONTEXT_HEADER;
    object_md_t object_md;
} object_callback_context_t;

static ebpf_result_t
_ebpf_object_context_create(
    _In_reads_bytes_opt_(data_size_in) const uint8_t* data_in,
    size_t data_size_in,
    _In_reads_bytes_opt_(context_size_in) const uint8_t* context_in,
    size_t context_size_in,
    _Outptr_ void** context)
{
    EBPF_EXT_LOG_ENTRY();
    ebpf_result_t result;
    object_callback_context_t* object_context = NULL;

    *context = NULL;

    UNREFERENCED_PARAMETER(data_in);
    UNREFERENCED_PARAMETER(data_size_in);

    if (context_in == NULL || context_size_in < sizeof(object_md_t)) {
        EBPF_EXT_LOG_MESSAGE(EBPF_EXT_TRACELOG_LEVEL_ERROR, EBPF_EXT_TRACELOG_KEYWORD_BASE, "Context is required");
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    object_context = (object_callback_context_t*)ExAllocatePoolUninitialized(
        NonPagedPoolNx, sizeof(object_callback_context_t), EBPF_EXTENSION_POOL_TAG);
    EBPF_EXT_BAIL_ON_ALLOC_FAILURE_RESULT(
        EBPF_EXT_TRACELOG_KEYWORD_BASE, object_context, "object_context", result);

    // Copy the context from the caller.
    memcpy(object_context, context_in, sizeof(object_md_t));

    *context = object_context;
    object_context = NULL;
    result = EBPF_SUCCESS;

Exit:
    if (object_context) {
        ExFreePool(object_context);
        object_context = NULL;
    }
    EBPF_EXT_RETURN_RESULT(result);
}

static void
_ebpf_object_context_destroy(
    _In_opt_ void* context,
    _Out_writes_bytes_to_(*data_size_out, *data_size_out) uint8_t* data_out,
    _Inout_ size_t* data_size_out,
    _Out_writes_bytes_to_(*context_size_out, *context_size_out) uint8_t* context_out,
    _Inout_ size_t* context_size_out)
{
    EBPF_EXT_LOG_ENTRY();

    UNREFERENCED_PARAMETER(data_out);

    object_callback_context_t* object_context = (object_callback_context_t*)context;
    object_md_t* object_context_out = (object_md_t*)context_out;

    if (!object_context) {
        goto Exit;
    }

    if (context_out != NULL && *context_size_out >= sizeof(object_md_t)) {
        // Copy the context to the caller.
        memcpy(object_context_out, &object_context->object_md, sizeof(object_md_t));
        *context_size_out = sizeof(object_md_t);
    } else {
        *context_size_out = 0;
    }

    // No data to copy for objects
    *data_size_out = 0;

    ExFreePool(object_context);

Exit:
    EBPF_EXT_LOG_EXIT();
}

OB_PREOP_CALLBACK_STATUS
_ebpf_object_pre_operation_callback(
    _In_ PVOID registration_context,
    _In_ POB_PRE_OPERATION_INFORMATION operation_information)
{
    UNREFERENCED_PARAMETER(registration_context);

    object_callback_context_t object_callback_context = {.object_md = {0}};

    EBPF_EXT_LOG_ENTRY();
    ebpf_extension_hook_client_t* client_context;

    // Determine object type
    if (operation_information->ObjectType == *PsProcessType) {
        object_callback_context.object_md.object_type = OBJECT_TYPE_PROCESS;
        PEPROCESS process = (PEPROCESS)operation_information->Object;
        object_callback_context.object_md.object_pointer = (uint64_t)process;
        object_callback_context.object_md.target_process_id = (uint64_t)PsGetProcessId(process);
        object_callback_context.object_md.target_thread_id = 0;
    } else if (operation_information->ObjectType == *PsThreadType) {
        object_callback_context.object_md.object_type = OBJECT_TYPE_THREAD;
        PETHREAD thread = (PETHREAD)operation_information->Object;
        object_callback_context.object_md.object_pointer = (uint64_t)thread;
        object_callback_context.object_md.target_thread_id = (uint64_t)PsGetThreadId(thread);
        object_callback_context.object_md.target_process_id = (uint64_t)PsGetThreadProcessId(thread);
    } else {
        // Unknown object type, should not happen
        EBPF_EXT_LOG_EXIT();
        return OB_PREOP_SUCCESS;
    }

    // Set operation type
    if (operation_information->Operation == OB_OPERATION_HANDLE_CREATE) {
        object_callback_context.object_md.operation = OBJECT_OPERATION_HANDLE_CREATE;
    } else if (operation_information->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        object_callback_context.object_md.operation = OBJECT_OPERATION_HANDLE_DUPLICATE;
    }

    // Get source process and thread information
    object_callback_context.object_md.source_process_id = (uint64_t)PsGetCurrentProcessId();
    object_callback_context.object_md.source_thread_id = (uint64_t)PsGetCurrentThreadId();

    // Store the desired access
    if (operation_information->Operation == OB_OPERATION_HANDLE_CREATE) {
        object_callback_context.object_md.desired_access = operation_information->Parameters->CreateHandleInformation.DesiredAccess;
        object_callback_context.object_md.original_desired_access = operation_information->Parameters->CreateHandleInformation.OriginalDesiredAccess;
    } else {
        object_callback_context.object_md.desired_access = operation_information->Parameters->DuplicateHandleInformation.DesiredAccess;
        object_callback_context.object_md.original_desired_access = operation_information->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;
    }

    // For each attached client call the object hook.
    ebpf_result_t result;
    client_context = ebpf_extension_hook_get_next_attached_client(_ebpf_object_hook_provider_context, NULL);
    while (client_context != NULL) {
        NTSTATUS status = 0;
        if (ebpf_extension_hook_client_enter_rundown(client_context)) {
            result = ebpf_extension_hook_invoke_program(
                client_context, &object_callback_context.object_md, (uint32_t*)&status);
            if (result != EBPF_SUCCESS) {
                EBPF_EXT_LOG_MESSAGE(
                    EBPF_EXT_TRACELOG_LEVEL_ERROR,
                    EBPF_EXT_TRACELOG_KEYWORD_BASE,
                    "ebpf_extension_hook_invoke_program failed");
            }

            // If eBPF program modified the desired access, apply it
            if (result == EBPF_SUCCESS && !NT_SUCCESS(status)) {
                // Program denied the operation
                if (operation_information->Operation == OB_OPERATION_HANDLE_CREATE) {
                    operation_information->Parameters->CreateHandleInformation.DesiredAccess = 0;
                } else {
                    operation_information->Parameters->DuplicateHandleInformation.DesiredAccess = 0;
                }
            } else if (result == EBPF_SUCCESS) {
                // Update desired access if the program modified it
                if (operation_information->Operation == OB_OPERATION_HANDLE_CREATE) {
                    operation_information->Parameters->CreateHandleInformation.DesiredAccess =
                        object_callback_context.object_md.desired_access;
                } else {
                    operation_information->Parameters->DuplicateHandleInformation.DesiredAccess =
                        object_callback_context.object_md.desired_access;
                }
            }

            ebpf_extension_hook_client_leave_rundown(client_context);
        } else {
            EBPF_EXT_LOG_MESSAGE(
                EBPF_EXT_TRACELOG_LEVEL_ERROR,
                EBPF_EXT_TRACELOG_KEYWORD_BASE,
                "ebpf_extension_hook_client_enter_rundown failed");
        }

        client_context =
            ebpf_extension_hook_get_next_attached_client(_ebpf_object_hook_provider_context, client_context);
    }

    EBPF_EXT_LOG_EXIT();
    return OB_PREOP_SUCCESS;
}

_Success_(return >= 0) static int32_t _ebpf_object_get_image_path(
    _In_ object_md_t* object_md, _Out_writes_bytes_(path_length) uint8_t* path, uint32_t path_length)
{
    CONTAINING_RECORD(object_md, object_callback_context_t, object_md);

    int32_t result = 0;

    // Get the image path of the target process
    PEPROCESS process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)object_md->target_process_id, &process);
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