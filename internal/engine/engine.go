package engine

import (
	"context"
	"fmt"
	"goste/internal/bpf"
	"os"
	"os/exec"
	"syscall"

	"debug/elf"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Config holds the configuration for the GoSTE Engine.
type Config struct {
	BinaryPath   string
	IsTracing    bool
	StateSymbols []string
}

type Engine struct {

	//Configs passed from main (parsed from cli)
	config Config

	executable *link.Executable
	bpfObjects bpf.GosteObjects

	// links holds all attached eBPF links (probes, tracepoints) for cleanup.
	links []link.Link
}

// NewEngine creates and initialises a new Engine with the provided configuration.
func NewEngine(cfg Config) (*Engine, error) {
	return &Engine{
		config: cfg,
	}, nil
}

func (e *Engine) Start(ctx context.Context) error {

	//Load and initialize eBPF maps and programs into the kernel

	if err := e.loadBpfObjects(); err != nil {
		return err
	}

	if err := e.initEmptyMaps(); err != nil {
		return fmt.Errorf("initializing empty maps: %w", err)
	}

	//Open the executable target

	var err error
	e.executable, err = link.OpenExecutable(e.config.BinaryPath)
	if err != nil {
		return fmt.Errorf("opening executable %s: %w", e.config.BinaryPath, err)
	}

	if err := e.attachGoProbes(); err != nil {
		return err
	}

	fmt.Printf("Engine ready. Starting target: %s\n", e.config.BinaryPath)

	pid, err := e.runTarget(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Tracing task with PID: %d\n", pid)

	// Keep the method alive until context is cancelled (e.g. via Ctrl+C)
	<-ctx.Done()
	return nil
}

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

	// Set max entries for the state_map
	if m, ok := spec.Maps["state_map"]; ok {
		m.MaxEntries = uint32(len(e.config.StateSymbols) + 1)
	}

	if err := spec.LoadAndAssign(&e.bpfObjects, nil); err != nil {
		return fmt.Errorf("loading BPF objects: %w", err)
	}
	return nil
}

func (e *Engine) runTarget(ctx context.Context) (int, error) {
	cmd := exec.CommandContext(ctx, e.config.BinaryPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// CONCEPT: ask kernel to stop task right after syscall 'exec'
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Ptrace: true,
	}

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("starting target: %w", err)
	}

	pid := cmd.Process.Pid

	// Attach uprobe with pid passed to kernel via cookie
	if err := e.attachEntryPointUprobe(pid); err != nil {
		syscall.PtraceDetach(pid)
		return 0, err
	}

	syscall.PtraceDetach(pid)

	go func() {
		err := cmd.Wait()
		fmt.Printf("\n[Engine] Target process (PID %d) exited: %v\n", pid, err)
	}()

	return pid, nil
}

// initEmptyMaps populates the eBPF maps with initial empty values where necessary.
func (e *Engine) initEmptyMaps() error {

	for i := 0; i <= len(e.config.StateSymbols); i++ {
		state := bpf.GosteAppState{} // All-zero initialized structure
		if err := e.bpfObjects.StateMap.Update(uint32(i), &state, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("initializing state_map at index %d: %w", i, err)
		}
	}

	return nil
}

func (e *Engine) attachEntryPointUprobe(pid int) error {
	// Read the entry point from the ELF header of the target binary
	f, err := elf.Open(e.config.BinaryPath)
	if err != nil {
		return fmt.Errorf("opening ELF: %w", err)
	}
	defer f.Close()

	entryPointVA := f.Entry

	// Translating VA to real offlse
	entryPointOffset, err := getOffsetFromVA(f, entryPointVA)
	if err != nil {
		return fmt.Errorf("calculating entry point offset: %w", err)
	}

	up, err := e.executable.Uprobe("", e.bpfObjects.TraceEntryPoint, &link.UprobeOptions{
		Address: entryPointOffset,
		Cookie:  uint64(pid),
	})

	if err != nil {
		return fmt.Errorf("attaching entry point uprobe: %w", err)
	}

	e.links = append(e.links, up)
	return nil
}

func getOffsetFromVA(f *elf.File, va uint64) (uint64, error) {
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_LOAD {
			if va >= prog.Vaddr && va < prog.Vaddr+prog.Filesz {
				return va - prog.Vaddr + prog.Off, nil
			}
		}
	}
	return 0, fmt.Errorf("cant map virtuall adrees %x to offset", va)
}

func (e *Engine) attachGoProbes() error {

	up, err := e.executable.Uprobe("runtime.mstart.abi0", e.bpfObjects.MarkGoThread, nil)
	if err != nil {
		up, err = e.executable.Uprobe("runtime.mstart0", e.bpfObjects.MarkGoThread, nil)
		if err != nil {
			return fmt.Errorf("attaching uprobe to runtime.mstart variants: %w", err)
		}
	}

	e.links = append(e.links, up)

	return nil
}

// Stop detaches all probes and unloads the eBPF objects cleanly.
func (e *Engine) Stop() {
	// Close all attached BPF links
	for _, l := range e.links {
		if l != nil {
			l.Close()
		}
	}
	e.links = nil

	e.bpfObjects.Close()

	if e.executable != nil {
		// Note: link.Executable doesn't have a Close() method in current cilium/ebpf link API.
	}

}
