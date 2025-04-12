#pragma once
#include <stddef.h>
#include <stdint.h>

typedef struct _regevent_md
{
    uint8_t* event_data_start; ///< Pointer to start of the data associated with the event.
    uint8_t* event_data_end;   ///< Pointer to end of the data associated with the event.

} regevent_md_t;


typedef int
regevent_event_hook_t(regevent_md_t* context);

// RegEvent helper functions.
#define REGEVENT_EXT_HELPER_FN_BASE 0xFFFF

#if !defined(__doxygen) && !defined(EBPF_HELPER)
#define EBPF_HELPER(return_type, name, args) typedef return_type(*name##_t) args
#endif

typedef enum
{
    BPF_FUNC_regevent_push_event = REGEVENT_EXT_HELPER_FN_BASE + 1,
} ebpf_regevent_event_helper_id_t;

/**
 * @brief Push an event to the netevent event ring buffer.
 *
 * @param[in] context Event metadata.
 *
 * @retval =0 Succeeded inserting the event.
 * @retval <0 A failure occurred.
 */
EBPF_HELPER(int, bpf_regevent_push_event, (regevent_md_t * ctx));
#ifndef __doxygen
#define bpf_regevent_push_event ((bpf_regevent_push_event_t)BPF_FUNC_regevent_push_event)
#endif
