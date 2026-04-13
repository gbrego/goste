// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

// task_state_map value for go threads
#define GO_THREAD_MARKER 0xFFFFFFFF
#define NOF_SYSCALLS 512
#define MAX_STATES 16

/* Execution mode: tracing vs enforcement */
const volatile bool is_tracing = true;

struct goroutine_id {
  __u32 tgid;
  __u32 _pad; // padding: must be set to 0, needed to align to 16 bytes
  __u64 goid;
};

// each state has a "bool" array of allowed syscalls and a "bool" array of next
// states syscalls[i] = 1 means syscall i is allowed, i is the syscall id
// next_state[i] = 1 means state i is a possible next state, i is the state id
struct app_state {
  uint8_t syscalls[NOF_SYSCALLS];
  uint8_t next_state[MAX_STATES];
};

// task_tracee_map: TASK_STORAGE Map
// Key: int (represents the task_struct, handled internally by BPF task_storage)
// Value: u32 it distingueshes non go threads from go threads, and in the first
// stores current state id
//   If value < 0xFFFF: non-Go thread (direct state_id)
//   If value == GO_THREAD_MARKER: Go thread (perform lookup in
//   goroutine_tracee_map)
struct {
  __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, int);
  __type(value, __u32); // task state_id or GO_THREAD_MARKER
} task_tracee_map SEC(".maps");

// goroutine_tracee_map: HASH Map
// Key: struct goroutine_id {tgid, goid} to avoid cross-process collisions
// Value: u32 (Goroutine state_id)
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 65536); // SHOULD COVER ALL GOROUTINES
  __type(key, struct goroutine_id);
  __type(value, __u32); // goroutine state_id
} goroutine_tracee_map SEC(".maps");

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

//__always_inline is used by the compiler to copy this code directly in the
// calling functions
static __always_inline void trace_task(struct task_struct *task) {
  __u32 *state = bpf_task_storage_get(&task_tracee_map, task, NULL,
                                      BPF_LOCAL_STORAGE_GET_F_CREATE);
  if (state) {
    *state = 0; // Initialize to starting state
  }
}

SEC("uprobe/runtime.mstart")
int mark_go_thread(struct pt_regs *ctx) {
  struct task_struct *task = bpf_get_current_task_btf();

  __u32 *state = bpf_task_storage_get(&task_tracee_map, task, NULL,
                                      BPF_LOCAL_STORAGE_GET_F_CREATE);
  if (!state)
    return 0;

  *state = GO_THREAD_MARKER;

  return 0;
}

SEC("uprobe/trace_entry_point")
int trace_entry_point(struct pt_regs *ctx) {

  __u64 target_tgid = bpf_get_attach_cookie(ctx);

  __u32 current_tgid = bpf_get_current_pid_tgid() >> 32;

  if (current_tgid != (__u32)target_tgid) {
    return 0;
  }

  struct task_struct *task = bpf_get_current_task_btf();
  trace_task(task);

  bpf_printk("Trace entry point triggered for PID %d. Task added to map.\n",
             current_tgid);

  return 0;
}
