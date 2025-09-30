// Sample eBPF program to test thread monitoring
// This is a basic test program to demonstrate the threadeventebpfext extension

#include "ebpf_ntos_hooks.h"

SEC("thread")
int thread_monitor(thread_md_t* ctx)
{
    // Log thread creation/deletion events
    if (ctx->operation == THREAD_OPERATION_CREATE) {
        // Thread created - process ID: ctx->process_id, thread ID: ctx->thread_id
        return 0; // Allow the operation
    } else if (ctx->operation == THREAD_OPERATION_DELETE) {
        // Thread terminated - process ID: ctx->process_id, thread ID: ctx->thread_id
        return 0; // Allow the operation (return value ignored for delete operations)
    }

    return 0; // Allow all operations by default
}