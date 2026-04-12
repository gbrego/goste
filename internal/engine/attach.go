package engine

import (
	"context"
	"fmt"
	"goste/internal/bpf"
	"os"
	"os/exec"

	"github.com/cilium/ebpf/link"
)

// Config holds the configuration for the GoSTE Engine.
type Config struct {
	BinaryPath   string
	IsTracing    bool
	StateSymbols []string
}

// Engine is the central component of GoSTE.
// It is responsible for:
//   - Loading the compiled eBPF objects into the kernel.
//   - Attaching uprobes for goroutine lifecycle and state-transition tracking.
//   - Attaching the syscall enforcement tracepoint.
//   - Reading events from the eBPF ring buffer and dispatching them.
type Engine struct {

	//Configs passed from main (parsed from cli)
	config Config

	executable *link.Executable
	bpfObjects bpf.GosteObjects

	// TODO: hold attached links (goroutine uprobes, tracepoint)
}

// NewEngine creates and initialises a new Engine with the provided configuration.
func NewEngine(cfg Config) (*Engine, error) {
	return &Engine{
		config: cfg,
	}, nil
}

// Start loads the eBPF programs into the kernel, attaches all probes,
// and begins reading events. It blocks until the context is cancelled.
func (e *Engine) Start(ctx context.Context) error {
	// 1. Load eBPF maps and programs into the kernel
	if err := e.loadBpfObjects(); err != nil {
		return err
	}

	// 2. Open the executable target to find symbols for uprobes
	var err error
	e.executable, err = link.OpenExecutable(e.config.BinaryPath)
	if err != nil {
		return fmt.Errorf("opening executable %s: %w", e.config.BinaryPath, err)
	}

	// TODO: attach goroutine uprobes (using e.executable)
	// TODO: attach state-transition uprobes (using e.config.StateSymbols)
	// TODO: attach sys_enter tracepoint
	// TODO: start ring buffer read loop

	fmt.Printf("Engine pronto. Avvio del target: %s\n", e.config.BinaryPath)

	// 3. Launch the target process and retrieve its PID
	pid, err := e.runTarget(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Tracciamento in corso per il PID: %d\n", pid)

	// Keep the method alive until context is cancelled (e.g. via Ctrl+C)
	<-ctx.Done()
	return nil
}

// runTarget executes the target binary and returns its PID immediately.
// It uses the provided context to kill the process if the context is cancelled.
// A background goroutine is used to wait for the process completion.
func (e *Engine) runTarget(ctx context.Context) (int, error) {
	cmd := exec.CommandContext(ctx, e.config.BinaryPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("starting target: %w", err)
	}

	pid := cmd.Process.Pid

	// Monitor the process in background to prevent zombie processes and handle cleanup
	go func() {
		err := cmd.Wait()
		fmt.Printf("\n[Engine] Target process (PID %d) exited: %v\n", pid, err)
	}()

	return pid, nil
}

// loadBpfObjects loads the compiled eBPF objects into the kernel.
// It also rewrites the 'is_tracing' constant based on the Engine configuration.
func (e *Engine) loadBpfObjects() error {
	spec, err := bpf.LoadGoste()
	if err != nil {
		return fmt.Errorf("loading BPF spec: %w", err)
	}

	// Set the 'is_tracing' constant in the BPF code via the Variables map
	if v, ok := spec.Variables["is_tracing"]; ok {
		if err := v.Set(e.config.IsTracing); err != nil {
			return fmt.Errorf("setting is_tracing variable: %w", err)
		}
	} else {
		return fmt.Errorf("variable 'is_tracing' not found in BPF spec")
	}

	if err := spec.LoadAndAssign(&e.bpfObjects, nil); err != nil {
		return fmt.Errorf("loading BPF objects: %w", err)
	}
	return nil
}

// Stop detaches all probes and unloads the eBPF objects cleanly.
func (e *Engine) Stop() {
	e.bpfObjects.Close()

	if e.executable != nil {
		// Note: link.Executable doesn't have a Close() method in current cilium/ebpf link API.
	}

	// TODO: close attached links
}
