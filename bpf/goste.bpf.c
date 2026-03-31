// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

// la struttura dell'evento che mandiamo a Go
// DEVE essere identica alla struct Go generata da bpf2go
struct event {
  __u32 pid;        // process ID
  __u32 syscall_nr; // numero della syscall
  char comm[16];    // nome del processo (es. "bash", "nginx")
};

// la ring buffer — canale kernel → userspace
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24); // 16MB di buffer
  __type(value, struct event);  // <-- LA MACRO MAGICA CHE CERCAVI
} events SEC(".maps");

// il programma BPF — agganciato al tracepoint sys_enter
// viene eseguito ogni volta che QUALSIASI processo fa una syscall
SEC("tracepoint/raw_syscalls/sys_enter")
int monitor_syscall(struct trace_event_raw_sys_enter *ctx) {

  // alloca spazio per l'evento nella ringbuf
  struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e) {
    return 0; // ringbuf piena, evento perso
  }

  // riempi l'evento con i dati
  e->pid = bpf_get_current_pid_tgid() >> 32; // prendi solo il PID (32 bit alti)
  e->syscall_nr = ctx->id;                   // numero della syscall
  bpf_get_current_comm(&e->comm, sizeof(e->comm)); // nome del processo

  // manda l'evento a userspace
  bpf_ringbuf_submit(e, 0);
  return 0;
}

// A simple uprobe hook, testing the execution of the monitor_syscall_event.
// IMPORTANT: this is a hook, i net do specify the section so that celium/ebpf
// can find it and execute it the right way

// LEARNING: questa non è è la uprobe stessa: è la funzione che viene lanciata
// quando la probe è triggerata

// SEC("uprobe/test_syscomb")
// int monitor_syscall_event(struct pt_regs *ctx) {
//   bpf_printk("GoSTE: syscall event intercepted!\\n");
//   return 0;
// }
