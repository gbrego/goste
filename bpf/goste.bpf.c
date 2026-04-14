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

/* Offset of the goid field in the runtime.g struct */
const volatile __u64 goid_offset = 0;

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

// pending_goroutines: HASH Map
// Key: u64 (tgid_pid from bpf_get_current_pid_tgid)
// Value: u32 (Goroutine state_id to be inherited)
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, __u64);
  __type(value, __u32);
} pending_goroutines SEC(".maps");

//__always_inline is used by the compiler to copy this code directly in the
// calling functions

static __always_inline __u32 *trace_task(struct task_struct *task,
                                         struct task_struct *parent) {
  __u32 *task_state = bpf_task_storage_get(&task_tracee_map, task, NULL,
                                           BPF_LOCAL_STORAGE_GET_F_CREATE);
  if (!task_state)
    return NULL;

  *task_state = 0;

  if (parent) {
    __u32 *parent_state =
        bpf_task_storage_get(&task_tracee_map, parent, NULL, 0);

    if (parent_state && *parent_state != GO_THREAD_MARKER) {
      *task_state = *parent_state;
    }
  }
  return task_state;
}

SEC("uprobe/runtime.mstart")
int mark_go_thread(struct pt_regs *ctx) {
  struct task_struct *task = bpf_get_current_task_btf();

  __u32 *state = bpf_task_storage_get(&task_tracee_map, task, NULL, 0);
  if (!state)
    return 0;

  *state = GO_THREAD_MARKER;

  bpf_printk("New Go stask PID: %d", task->pid);

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
  trace_task(task, NULL);

  bpf_printk("Trace entry point triggered for PID %d. Task added to map.\n",
             current_tgid);

  return 0;
}

// BPF_PROG is a macro that helps passing arguments such as parent and child
// task_struct
SEC("tp_btf/sched_process_fork")
int BPF_PROG(inherit_state_info, struct task_struct *parent,
             struct task_struct *child) {

  __u32 *parent_state = bpf_task_storage_get(&task_tracee_map, parent, NULL, 0);

  if (!parent_state) {
    return 0;
  }

  __u32 *child_state = trace_task(child, parent);
  if (!child_state) {
    bpf_printk("Error: failed to inherit state for child PID %d", child->pid);
    return 1;
  }
  bpf_printk("State inherited: parent PID %d -> child PID %d (state_id=0x%x)",
             parent->pid, child->pid, *child_state);
  return 0;
}

SEC("uprobe/trace_new_goroutine")
int trace_new_goroutine(struct pt_regs *ctx) {
  void *parent_g = (void *)ctx->r14;
  if (!parent_g)
    return 0;

  __u64 parent_goid;
  bpf_probe_read_user(&parent_goid, sizeof(parent_goid),
                      parent_g + goid_offset);

  __u32 tgid = bpf_get_current_pid_tgid() >> 32;
  struct goroutine_id key = {.tgid = tgid, .goid = parent_goid, ._pad = 0};

  __u32 state_to_save;
  __u32 *state_id = bpf_map_lookup_elem(&goroutine_tracee_map, &key);

  if (state_id) {
    state_to_save = *state_id;
    bpf_printk("G_ENTRY: found parent goid=%llu in map, state=%d\n",
               parent_goid, state_to_save);
  } else {
    // bootstrap case, parent is not traced
    struct task_struct *task = bpf_get_current_task_btf();
    __u32 *task_state = bpf_task_storage_get(&task_tracee_map, task, 0, 0);

    // only trace first goroutine, if a goroutine is not created by a fellow
    // gorouine and the parent task is traced as 0xFFFFFFFF that it's a go
    // system goroutine, tracing it is futilem since if compromized it means the
    // whole runtime is compromized and therefore goste is powerless
    if (task_state && *task_state != GO_THREAD_MARKER) {
      state_to_save = *task_state;
      bpf_printk("G_ENTRY: bootstrap seed from task state=%d\n", state_to_save);
    } else {
      return 0;
    }
  }

  __u64 tgid_pid = bpf_get_current_pid_tgid();
  bpf_map_update_elem(&pending_goroutines, &tgid_pid, &state_to_save, BPF_ANY);

  return 0;
}

SEC("uprobe/runtime.runqput")
int complete_trace_new_goroutine(struct pt_regs *ctx) {
  __u64 tgid_pid = bpf_get_current_pid_tgid();

  // Check if we saved a state from the entry probe for this thread
  __u32 *state_id = bpf_map_lookup_elem(&pending_goroutines, &tgid_pid);
  if (!state_id)
    return 0;

  __u32 state_to_save = *state_id;
  bpf_map_delete_elem(&pending_goroutines, &tgid_pid);

  // In ABIInternal, the second argument (gp *g) of runqput is in RBX
  void *child_g = (void *)ctx->bx;
  if (!child_g)
    return 0;

  __u64 child_goid;
  bpf_probe_read_user(&child_goid, sizeof(child_goid), child_g + goid_offset);

  __u32 tgid = tgid_pid >> 32;
  struct goroutine_id key = {.tgid = tgid, .goid = child_goid, ._pad = 0};

  bpf_map_update_elem(&goroutine_tracee_map, &key, &state_to_save, BPF_ANY);
  bpf_printk("G_RUNQ: goid=%llu, state=%d, tid=%u\n", child_goid, state_to_save,
             (__u32)tgid_pid);

  return 0;
}

SEC("uprobe/runtime.goexit1")
int remove_exiting_goroutine(struct pt_regs *ctx) {
  void *g = (void *)ctx->r14;
  if (!g)
    return 0;

  __u64 goid;
  bpf_probe_read_user(&goid, sizeof(goid), g + goid_offset);

  __u32 tgid = bpf_get_current_pid_tgid() >> 32;
  struct goroutine_id key = {.tgid = tgid, .goid = goid, ._pad = 0};

  // Clean up goroutine state when it exits
  bpf_map_delete_elem(&goroutine_tracee_map, &key);

  return 0;
}
