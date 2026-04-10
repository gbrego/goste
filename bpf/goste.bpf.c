// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

// task_state_map value for go threads
#define GO_THREAD_MARKER 0xFFFFFFFF
#define NOF_SYSCALLS 512
#define MAX_STATES 16

struct goroutine_id {
  __u32 tgid;
  __u64 goid;
  __u32 _pad; // padding: must be set to 0, needed to align to 16 bytes
};

// each state has a "bool" array of allowed syscalls and a "bool" array of next
// states syscalls[i] = 1 means syscall i is allowed, i is the syscall id
// next_state[i] = 1 means state i is a possible next state, i is the state id
struct app_state {
  uint8_t syscalls[NOF_SYSCALLS];
  uint8_t next_state[MAX_STATES];
};

// task_trace_map: TASK_STORAGE Map
// Key: int (represents the task_struct, handled internally by BPF task_storage)
// Value: u32 it distingueshes non go threads from go threads, and in the first
// stores current state id
//   If value < 0xFFFF: non-Go thread (direct state_id)
//   If value == GO_THREAD_MARKER: Go thread (perform lookup in
//   goroutine_trace_map)
struct {
  __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, int);
  __type(value, __u32); // task state_id or GO_THREAD_MARKER
} task_trace_map SEC(".maps");

// goroutine_trace_map: HASH Map
// Key: struct goroutine_id {tgid, goid} to avoid cross-process collisions
// Value: u32 (Goroutine state_id)
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240); // DO BE DEFINED IN USERSPACE
  __type(key, struct goroutine_id);
  __type(value, __u32); // goroutine state_id
} goroutine_trace_map SEC(".maps");

// state_map: ARRAY Map
// Key: u32 state_id
// Value: struct app_state (Policy: transition matrix and allowed syscalls)
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 256); // TO BE DEFINED IN USERSPACE
  __type(key, __u32);       // state_id (which is simply the index of the array)
  __type(value, struct app_state);
} state_map SEC(".maps");

// TODO: attach uprobes for goroutine lifecycle tracking
//   (runtime.newproc1, runtime.goexit1)

// TODO: attach uprobes for state-transition functions defined by the user

// TODO: attach tracepoint/raw_syscalls/sys_enter for enforcement
