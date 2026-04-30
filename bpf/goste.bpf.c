// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

/* From arch/x86/include/asm/thread_info.h */
#define TS_COMPAT 0x0002 /* 32bit syscall active (64BIT) */

/* task_state_map marker for go threads */
#define GO_THREAD_MARKER 0xFFFFFFFF

#define NOF_SYSCALLS 512
#define MAX_STATES 16

/* From include/uapi/asm-generic/signal.h */
#define SIGKILL 9

/* Action to take when a syscall filter violation is detected */
#define ACTION_LOG 0
#define ACTION_ERRNO 1
#define ACTION_KILL 2

/* Execution mode: tracing vs enforcement */
const volatile bool is_tracing = true;
const volatile __u32 enforce_action = 0;
const volatile int error_code = 1; // Default to EPERM

/* Current process is a child process of goste*/
const volatile bool is_child_process = true;

/* Filtering criteria */
const volatile pid_t targ_tgid = 0;

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

static __always_inline __u32 *add_to_tracee_map(struct task_struct *task,
                                                __u32 *state_id) {
  __u32 root_state_id = 0;
  if (!state_id) {
    state_id = &root_state_id;
  }

  return bpf_task_storage_get(&task_tracee_map, task, state_id,
                              BPF_LOCAL_STORAGE_GET_F_CREATE);
}

static __always_inline __u32 *trace_task(struct task_struct *task,
                                         struct task_struct *parent) {
  __u32 *initial_state = NULL;

  if (parent) {
    __u32 *parent_state =
        bpf_task_storage_get(&task_tracee_map, parent, NULL, 0);

    if (parent_state && *parent_state != GO_THREAD_MARKER) {
      initial_state = parent_state;
    }
  }

  return add_to_tracee_map(task, initial_state);
}

/* INHERITED AND MODIFIED FROM SYSCOMB
 * when target is not run by goste (is_child_process = true) this functions
 * checs if the detected task is must be traced
 */

static bool to_trace(pid_t pid, pid_t tgid) {
  /* filters */
  if (is_child_process)
    // When running the tracee as a child process we activate tracing
    // after the successful execution of execve
    return false;
  if (targ_tgid && targ_tgid != tgid)
    return false;
  return true;
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

/* Recover goid from a goroutine pointer */
static __always_inline __u64 get_goid(void *g) {
  __u64 goid = 0;
  if (!g)
    return 0;

  bpf_probe_read_user(&goid, sizeof(goid), g + goid_offset);
  return goid;
}

static __always_inline __u32 *get_goroutine_state_id(struct pt_regs *regs) {

  __u64 g_ptr = 0;
  // safely read r14, works for both Tracepoints and Kprobes
  bpf_probe_read_kernel(&g_ptr, sizeof(g_ptr), &regs->r14);

  __u64 goid = get_goid((void *)g_ptr);
  // sanity check: ignore invalid or suspiciously large goids (junk memory)
  // happens when Go threads execute syscalls while not hosting a goroutine
  // (internal runtime tasks)
  if (!goid || goid > 1000000000000ULL)
    return NULL;

  __u32 tgid = bpf_get_current_pid_tgid() >> 32;
  struct goroutine_id key = {.tgid = tgid, .goid = goid, ._pad = 0};

  __u32 *state_id = bpf_map_lookup_elem(&goroutine_tracee_map, &key);

  if (state_id)
    return state_id;

  // Goroutine not found:
  // this happens when live attaching to a go porgram
  // goroutine was created before the attach and therefore is still to be added
  // initiating with "flexibel" state 0 since we don't know waht stage the
  // target has reached

  __u32 initial_state = 0;
  bpf_map_update_elem(&goroutine_tracee_map, &key, &initial_state, BPF_NOEXIST);
  return bpf_map_lookup_elem(&goroutine_tracee_map, &key);
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

  if (*parent_state == GO_THREAD_MARKER) {
    struct pt_regs *user_regs = (struct pt_regs *)bpf_task_pt_regs(parent);
    parent_state = get_goroutine_state_id(user_regs);
  }

  if (!parent_state) {
    bpf_printk("Warning: forked process %d could not inherit state from parent "
               "goroutine",
               child->pid);
    // add_to_tracee_map will assign state 0 as default since state is NULL
  }

  __u32 *child_state = add_to_tracee_map(child, parent_state);

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
  __u64 parent_goid = get_goid((void *)ctx->r14);
  __u32 tgid = bpf_get_current_pid_tgid() >> 32;
  __u32 state_to_save;

  struct goroutine_id key = {.tgid = tgid, .goid = parent_goid, ._pad = 0};
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
    // system goroutine, tracing it is futile since if compromized it means the
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
  __u64 child_goid = get_goid((void *)ctx->bx);
  if (!child_goid)
    return 0;

  __u32 tgid = tgid_pid >> 32;
  struct goroutine_id key = {.tgid = tgid, .goid = child_goid, ._pad = 0};

  bpf_map_update_elem(&goroutine_tracee_map, &key, &state_to_save, BPF_ANY);
  bpf_printk("G_RUNQ: goid=%llu, state=%d, tid=%u\n", child_goid, state_to_save,
             (__u32)tgid_pid);

  return 0;
}

SEC("uprobe/runtime.goexit1")
int remove_exiting_goroutine(struct pt_regs *ctx) {
  __u64 goid = get_goid((void *)ctx->r14);
  if (!goid)
    return 0;

  __u32 tgid = bpf_get_current_pid_tgid() >> 32;
  struct goroutine_id key = {.tgid = tgid, .goid = goid, ._pad = 0};

  // Clean up goroutine state when it exits
  bpf_map_delete_elem(&goroutine_tracee_map, &key);

  return 0;
}

/*
 * INHERITED AND MODIFIED FROM SYSCOMB
 * Get the syscall bitmap of the current task or goroutine
 */
static __always_inline int get_current_syscall_bitmap(struct pt_regs *regs,
                                                      u8 **syscalls) {
  struct task_struct *task = bpf_get_current_task_btf();
  u32 *state_id = NULL, *success, root_state_id = 0;
  struct app_state *state;

  // Get application state from the tracee map
  state_id = bpf_task_storage_get(&task_tracee_map, task, NULL, 0);

  if (state_id /* is tracee */) {

    if (*state_id == GO_THREAD_MARKER) {
      state_id = get_goroutine_state_id(regs);
      if (!state_id)
        return 0;
    }

    state = bpf_map_lookup_elem(&state_map, state_id);
    if (!state) {
      bpf_printk("Error retrieving application state");
      return 1;
    }

    *syscalls = state->syscalls;
    return 0;
  }

  // Live tarcing mode: the first time a task that is to be traced is detected
  // it's added to the task_tracee_map with state 0

  if (to_trace(task->pid, task->tgid)) {
    success = trace_task(task, NULL);
    state = bpf_map_lookup_elem(&state_map, &root_state_id);
    if (!success || !state) {
      bpf_printk("Error adding task to the tracee task set");
      return 1;
    }

    *syscalls = state->syscalls;
    return 0;
  }

  return 0;
}

/*
 * INHERITED FROM SYSCOMB
 *
 * Monitor system call invocation to generate and enforce syscall filters.
 *
 * program is attached to syscall entry tracepoint only when generating
 * the filters.
 */

SEC("tp_btf/sys_enter")
void BPF_PROG(monitor_syscall_event, struct pt_regs *regs, long syscall_id) {
  u8 *syscalls;
  int err;
  struct task_struct *task;

  err = get_current_syscall_bitmap(regs, &syscalls);
  if (err || !syscalls /* non-tracee tasks */) {
    return;
  }

  // Tracee task

  // This is what seccomp does to distinguish 32-bit syscalls belonging to
  // the i386 ABI from syscalls belonging to the x86_64 and x32 ABIs
  // (see: arch/x86/include/asm/syscall.h#L167)
  task = bpf_get_current_task_btf();
  if (task->thread_info.status & TS_COMPAT) {
    // i386 ABI
    bpf_printk("Syscalls belonging to the i386 architecture are not "
               "supported");
    return;
  }

  // x86_64 or x32 ABI
  if (syscall_id >= NOF_SYSCALLS) {
    bpf_printk("Error invalid syscall number: %ld", syscall_id);
  } else if (syscall_id >= 0 && syscall_id < NOF_SYSCALLS) {
    if (is_tracing) {
      syscalls[syscall_id] = true;
      // too keep if light enforce log only option will be implemented
    } else if (!syscalls[syscall_id]) {
      bpf_printk("Syscall filter violation: syscall %d", syscall_id);
    }
  }
}

/*
 * INHERITED AND MODIFIED FROM SYSCOMB
 * Keep track of the transition between application states
 */
static int register_transition(u32 from, u32 to) {
  struct app_state *state;

  state = bpf_map_lookup_elem(&state_map, &from);
  if (!state) {
    bpf_printk("Error retrieving application state");
    return 1;
  }

  if (to >= MAX_STATES) {
    bpf_printk("Error state identifier exceeds the maximum number of "
               "states");
    return 1;
  }

  state->next_state[to] = true;

  return 0;
}

/* INHERITED AND MODIFIED FROM SYSCOMB
 * Check validity of the application state transition
 */
static int is_valid_transition(u32 from, u32 to) {
  // Asuming self transition only happens when a go preomption or stack growth
  // algorithm stops the goroutine and resumes it later making it hit the same
  // uprobe twice, besides, this check makes sense anyway, still there could be
  // something strange happening that gets ignore by this
  if (from == to) {
    return 1;
  }
  struct app_state *state;

  state = bpf_map_lookup_elem(&state_map, &from);
  if (!state) {
    bpf_printk("Error retrieving application state");
    return 0;
  }

  if (to >= MAX_STATES) {
    bpf_printk("Error state identifier exceeds the maximum number of states");
    return 0;
  }

  return state->next_state[to];
}

/*
 * INHERITED AND MODIFIED FROM SYSCOMB
 * Generic trigger representing a one-way application state transition.
 *
 * By keeping track of the application state transitions we can then replicate
 * the expected behavior of seccomp. Specifically, we can enforce syscall
 * filters that go from broader to stricter never allowing to acquire privileges
 * by moving to the next filter
 */
SEC("uprobe.multi")
int trigger_state_transition(struct pt_regs *ctx) {
  struct task_struct *task = bpf_get_current_task_btf();
  u32 *state_id, next_state_id, *success;
  int err;

  state_id = bpf_task_storage_get(&task_tracee_map, task, NULL, 0);

  if (state_id) {
    next_state_id = bpf_get_attach_cookie(ctx) + 1;

    if (*state_id == GO_THREAD_MARKER) {
      state_id = get_goroutine_state_id(ctx);
      if (!state_id) {
        return 0;
      }
    }

    if (is_tracing) {

      err = register_transition(*state_id, next_state_id);
      if (err) {
        bpf_printk("Error registering application state transition");
        return 1;
      }
    } else {
      if (!is_valid_transition(*state_id, next_state_id)) {
        if (is_child_process || *state_id) {
          bpf_printk("Flow integrity violation from %d to %d", *state_id,
                     next_state_id);
          bpf_send_signal(SIGKILL);
          return 1;
        } else {
          bpf_printk("Flow integrity warning from 0 to %d", next_state_id);
        }
      }
    }

    *state_id = next_state_id;

    return 0;
  }

  if (to_trace(task->pid, task->tgid)) {
    next_state_id = bpf_get_attach_cookie(ctx) + 1;
    success = add_to_tracee_map(task, &next_state_id);
    if (!success) {
      bpf_printk("Error adding task to the tracee task set");
      return 1;
    }
    return 0;
  }

  return 0;
}

/*
 * INHERITED AND MODIFIED FROM SYSCOMB
 * Apply the enforcement action according to the current configuration
 *
 * We always execute the override return function to ensure the code of
 * the system call is never being executed
 * (https://www.elastic.co/security-labs/signaling-from-within-how-ebpf-interacts-with-signals)
 */
static __always_inline void apply_enforce_action(struct pt_regs *ctx) {

  if (enforce_action == ACTION_KILL) {
    bpf_send_signal(SIGKILL);
  }

  bpf_override_return(ctx, -error_code);
}

/*
 * INHERITED AND MODIFIED FROM SYSCOMB
 * Enforce syscall filters with kill-process, kill-thread, and errno actions.
 *
 * We attach this program to error injection functions only when necessary
 * (i.e., when enforcing syscall filters with actions that must prevent the
 * execution of the syscall code).
 */
SEC("kprobe.multi")
int override_syscall_filter(struct pt_regs *ctx) {
  u8 *syscalls = NULL;
  int err;
  u64 syscall_id;
  struct task_struct *task;

  struct pt_regs *real_regs = (struct pt_regs *)ctx->di;
  err = get_current_syscall_bitmap(real_regs, &syscalls);

  if (err) {
    return 1;
  }

  // Ignore non-tracee tasks
  // WARNING: this logic does work in seccomb mode (state fallback, which is
  // currently the only mode) if least privilege mode is implemented, this logic
  // will either stay flawed like syscomb or must be changed: when live hooking
  // (-p) and get_current_syscall_bitmap detects a task that must be traced but
  // is not yet in the maps is gives it state 0, in least priviledge mode we
  // don't know what state the target is, and if state 0 does not support every
  // syscall supported by the acutal current state, the error in "mistakenly"
  // injected anyways

  if (!syscalls) {
    return 0;
  }

  // Tracee task

  syscall_id = bpf_get_attach_cookie(ctx);

  //
  // bpf_printk("syscall detected: %d", syscall_id);

  // This is what seccomp does to distinguish 32-bit syscalls belonging to
  // the i386 ABI from syscalls belonging to the x86_64 and x32 ABIs
  // (see: arch/x86/include/asm/syscall.h#L167)
  task = bpf_get_current_task_btf();
  if (task->thread_info.status & TS_COMPAT) {
    // i386 ABI
    bpf_printk("Syscalls belonging to the i386 architecture are not "
               "allowed");
    apply_enforce_action(ctx);
    return 0;
  }

  // x86_64 or x32 ABI

  if (syscall_id >= NOF_SYSCALLS) {
    bpf_printk("Error during syscall filter evaluation: invalid syscall "
               "number: %ld",
               syscall_id);
    apply_enforce_action(ctx);
    return 1;
  }

  //
  // bpf_printk("Tracing syscall: %ld", syscalls[syscall_id]); // TESTING

  if (!syscalls[syscall_id]) {
    bpf_printk("Syscall filter violation: syscall %d", syscall_id);
    apply_enforce_action(ctx);
  }

  return 0;
}