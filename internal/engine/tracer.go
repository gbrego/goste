package engine

import "context"

// Tracer is the central component of GoSTE.
// It is responsible for:
//   - Loading the compiled eBPF objects into the kernel.
//   - Attaching uprobes for goroutine lifecycle and state-transition tracking.
//   - Attaching the syscall enforcement tracepoint.
//   - Reading events from the eBPF ring buffer and dispatching them.
type Tracer struct {
	// TODO: hold loaded eBPF objects (bpf.GosteObjects)
	// TODO: hold attached links (goroutine uprobes, tracepoint)
	// TODO: hold ring buffer reader
}

// NewTracer creates and initialises a new Tracer.
func NewTracer() (*Tracer, error) {
	return &Tracer{}, nil
}

// Start loads the eBPF programs into the kernel, attaches all probes,
// and begins reading events. It blocks until ctx is cancelled.
func (t *Tracer) Start(ctx context.Context) error {
	// TODO: load eBPF objects with bpf.LoadGosteObjects()
	// TODO: attach goroutine uprobes
	// TODO: attach state-transition uprobes
	// TODO: attach sys_enter tracepoint
	// TODO: start ring buffer read loop
	return nil
}

// Stop detaches all probes and unloads the eBPF objects cleanly.
func (t *Tracer) Stop() {
	// TODO: close ring buffer reader
	// TODO: close attached links
	// TODO: close eBPF objects
}
