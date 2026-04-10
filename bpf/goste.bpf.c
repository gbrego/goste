// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define GO_THREAD_MARKER 0xFFFFFFFF


struct go_key {
	__u32 tgid;
	__u64 goid;
};

// Policy structure (adjacency matrix + syscall bitmap)
struct app_state {
	__u64 syscall_bitmap[8]; // 512 bits to represent allowed syscalls
	__u64 adjacency_matrix[4]; // Bitmap for allowed state transitions
};

// task_status_map: TASK_STORAGE Map
// Key: int (represents the task_struct, handled internally by BPF task_storage)
// Value: u32 (status/state)
//   If value < 0xFFFF: non-Go thread (direct state_id)
//   If value == GO_THREAD_MARKER: Go thread (perform lookup in go_state_map)
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, __u32);
} task_status_map SEC(".maps");

// go_state_map: HASH Map
// Key: struct go_key {tgid, goid} to avoid cross-process collisions
// Value: u32 (Goroutine state_id)
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 0); // Placeholder, MUST be overridden by userspace
	__type(key, struct go_key);
	__type(value, __u32);
} go_state_map SEC(".maps");

// state_map: ARRAY Map
// Key: u32 state_id
// Value: struct app_state (Policy: transition matrix and allowed syscalls)
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 0); // Placeholder, MUST be overridden by userspace
	__type(key, __u32);
	__type(value, struct app_state);
} state_map SEC(".maps");

// TODO: attach uprobes for goroutine lifecycle tracking
//   (runtime.newproc1, runtime.goexit1)

// TODO: attach uprobes for state-transition functions defined by the user

// TODO: attach tracepoint/raw_syscalls/sys_enter for enforcement
