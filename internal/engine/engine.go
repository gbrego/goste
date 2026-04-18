package engine

import (
	"context"
	"fmt"
	"goste/internal/bpf"
	"os"
	"os/exec"
	"syscall"

	"debug/dwarf"
	"debug/elf"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type StateSymbol struct {
	Path   string
	Symbol string
}

// Config holds the configuration for the GoSTE Engine.
type Config struct {
	BinaryPath    string
	IsTracing     bool
	EnforceAction uint32
	StateSymbols  []StateSymbol
	Policy        *Policy
}

const (
	ActionLog   uint32 = 0
	ActionErrno uint32 = 1
	ActionKill  uint32 = 2

	MaxSyscalls = 512
	MaxStates   = 16
)

type Engine struct {

	//Configs passed from main (parsed from cli)
	config Config

	executable *link.Executable
	bpfObjects bpf.GosteObjects

	// links holds all attached eBPF links (probes, tracepoints) for cleanup.
	links []link.Link
}

type probeTarget struct {
	variants []string
	program  *ebpf.Program
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

	if e.config.IsTracing {
		if err := e.initEmptyMaps(); err != nil {
			return fmt.Errorf("initializing empty maps: %w", err)
		}
	} else if e.config.Policy != nil {
		if err := e.initEnforcementMaps(); err != nil {
			return fmt.Errorf("initializing enforcement maps: %w", err)
		}
	}

	//Open the executable target

	var err error
	e.executable, err = link.OpenExecutable(e.config.BinaryPath)
	if err != nil {
		return fmt.Errorf("opening executable %s: %w", e.config.BinaryPath, err)
	}

	if err := e.attachCommonProbes(); err != nil {
		return err
	}

	if err := e.attachGoRuntimeProbes(); err != nil {
		return err
	}

	if e.config.IsTracing || e.config.EnforceAction == ActionLog {
		if err := e.attachTracingProbes(); err != nil {
			return err
		}
	} else {
		if err := e.attachEnforcementProbes(); err != nil {
			return err
		}
	}

	fmt.Printf("Engine ready. Starting target: %s\n", e.config.BinaryPath)

	pid, done, err := e.runTarget(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Tracing task with PID: %d\n", pid)

	// Wait for either the target to exit or a termination signal (Ctrl+C)
	select {
	case <-ctx.Done():
	case <-done:
	}

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
	}

	if v, ok := spec.Variables["enforce_action"]; ok {
		if err := v.Set(e.config.EnforceAction); err != nil {
			return fmt.Errorf("setting enforce_action variable: %w", err)
		}
	}

	goidOffset, err := getGoidOffset(e.config.BinaryPath)
	if err != nil {
		return fmt.Errorf("detecting goid offset: %w (ensure binary has DWARF symbols)", err)
	}
	fmt.Printf("Detected goid offset for 'runtime.g.goid': %x\n", goidOffset)

	if v, ok := spec.Variables["goid_offset"]; ok {
		if err := v.Set(uint64(goidOffset)); err != nil {
			return fmt.Errorf("setting goid_offset variable: %w", err)
		}
	} else {
		return fmt.Errorf("variable 'goid_offset' not found in BPF spec")
	}

	// Set max entries for the state_map
	if m, ok := spec.Maps["state_map"]; ok {
		numStates := uint32(len(e.config.StateSymbols) + 1)
		if !e.config.IsTracing && e.config.Policy != nil {
			numStates = uint32(len(e.config.Policy.States))
		}
		m.MaxEntries = numStates
	}

	if err := spec.LoadAndAssign(&e.bpfObjects, nil); err != nil {
		return fmt.Errorf("loading BPF objects: %w", err)
	}
	return nil
}

func getGoidOffset(binaryPath string) (int64, error) {
	f, err := elf.Open(binaryPath)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	d, err := f.DWARF()
	if err != nil {
		return 0, err
	}

	reader := d.Reader()
	for {
		entry, err := reader.Next()
		if err != nil || entry == nil {
			break
		}

		// skip everything that is not a struct
		if entry.Tag != dwarf.TagStructType {
			continue
		}

		// ask stdlib to parse the complete type
		typ, err := d.Type(entry.Offset)
		if err != nil {
			continue
		}

		st, ok := typ.(*dwarf.StructType)
		if !ok || st.StructName != "runtime.g" {
			continue
		}

		// iterate already parsed fields — no manual reader needed
		for _, field := range st.Field {
			if field.Name == "goid" {
				return field.ByteOffset, nil
			}
		}
	}

	return 0, fmt.Errorf("goid offset not found in %s", binaryPath)
}

// This function is to be skipped when attaching to a live process (PID provided by user)
func (e *Engine) runTarget(ctx context.Context) (int, <-chan error, error) {
	cmd := exec.CommandContext(ctx, e.config.BinaryPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	// CONCEPT: ask kernel to stop task right after syscall 'exec'
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Ptrace: true,
	}

	if err := cmd.Start(); err != nil {
		return 0, nil, fmt.Errorf("starting target: %w", err)
	}

	pid := cmd.Process.Pid
	done := make(chan error, 1)

	// Ptrace synchronization: wait for the initial stop signal (SIGTRAP) at execve.
	// This prevents cmd.Wait() from catching it by mistake and thinking the target crashed.
	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &ws, syscall.WSTOPPED, nil); err != nil {
		return 0, nil, fmt.Errorf("waiting for ptrace trap: %w", err)
	}

	// Attach uprobe with pid passed to kernel via cookie
	if err := e.attachEntryPointUprobe(pid); err != nil {
		syscall.PtraceDetach(pid)
		return 0, nil, err
	}

	syscall.PtraceDetach(pid)

	go func() {
		err := cmd.Wait()
		fmt.Printf("\n[Engine] Target process (PID %d) exited: %v\n", pid, err)
		done <- err
		close(done)
	}()

	return pid, done, nil
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

// initEnforcementMaps populates the eBPF maps with the provided policy.
func (e *Engine) initEnforcementMaps() error {
	if e.config.Policy == nil {
		return fmt.Errorf("no policy provided for enforcement mode")
	}

	bpfStates, err := e.config.Policy.MapToBPFStates()
	if err != nil {
		return fmt.Errorf("converting policy to BPF states: %w", err)
	}

	for id, state := range bpfStates {
		if err := e.bpfObjects.StateMap.Update(id, &state, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("populating state_map at index %d: %w", id, err)
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

func (e *Engine) attachGoRuntimeProbes() error {
	//Go symbols are in constant change, it is necessary to try multiple variants and keep the list updated
	probes := []probeTarget{
		{
			variants: []string{
				"runtime.mstart.abi0",
				"runtime.mstart0",
				"runtime.mstart",
			},
			program: e.bpfObjects.MarkGoThread,
		},
		{
			variants: []string{
				"runtime.newproc",
				"runtime.newproc.abi0",
			},
			program: e.bpfObjects.TraceNewGoroutine,
		},
		{
			variants: []string{
				"runtime.runqput",
			},
			program: e.bpfObjects.CompleteTraceNewGoroutine,
		},
		{
			variants: []string{
				"runtime.goexit1",
				"runtime.goexit1.abi0",
			},
			program: e.bpfObjects.RemoveExitingGoroutine,
		},
	}

	for _, probe := range probes {
		if err := e.tryAttachGoRuntimeProbeVariant(probe); err != nil {
			return err
		}
	}

	return nil
}

func (e *Engine) tryAttachGoRuntimeProbeVariant(probe probeTarget) error {
	for _, sym := range probe.variants {
		up, err := e.executable.Uprobe(sym, probe.program, nil)
		if err == nil {
			e.links = append(e.links, up)
			return nil
		}
	}
	return fmt.Errorf("No variant found for probe targeting %s", probe.variants[0])
}

// needed in both tracing and enforcment mode
func (e *Engine) attachCommonProbes() error {

	l, err := link.AttachTracing(link.TracingOptions{
		Program: e.bpfObjects.InheritStateInfo,
	})
	if err != nil {
		return fmt.Errorf("attaching sched_process_fork tracepoint: %w", err)
	}
	e.links = append(e.links, l)

	// Attach state transition triggers if symbols are provided
	if len(e.config.StateSymbols) > 0 {
		// Group symbols by executable path, so that uprobe-multi is attached only once per executable
		execMap := make(map[string][]int)
		for i, sym := range e.config.StateSymbols {
			execMap[sym.Path] = append(execMap[sym.Path], i)
		}

		fmt.Printf("[Engine] Attaching state triggers to symbols: %v\n", e.config.StateSymbols)

		for path, indices := range execMap {
			var exe *link.Executable
			var err error
			if path == e.config.BinaryPath {
				exe = e.executable
			} else {
				exe, err = link.OpenExecutable(path)
				if err != nil {
					return fmt.Errorf("opening executable %s for state trace: %w", path, err)
				}
			}

			symbols := make([]string, len(indices))
			cookies := make([]uint64, len(indices))
			for i, idx := range indices {
				symbols[i] = e.config.StateSymbols[idx].Symbol
				cookies[i] = uint64(idx) // The cookie maps directly to the global state ID across all binaries
			}

			um, err := exe.UprobeMulti(symbols, e.bpfObjects.TriggerStateTransition, &link.UprobeMultiOptions{
				Cookies: cookies,
			})
			if err != nil {
				return fmt.Errorf("attaching state transition uprobes to %s: %w", path, err)
			}
			e.links = append(e.links, um)
		}
	}

	return nil
}

func (e *Engine) attachTracingProbes() error {
	l, err := link.AttachTracing(link.TracingOptions{
		Program: e.bpfObjects.MonitorSyscallEvent,
	})
	if err != nil {
		return fmt.Errorf("attaching sys_enter tracepoint: %w", err)
	}
	e.links = append(e.links, l)
	return nil
}

func (e *Engine) attachEnforcementProbes() error {
	// TODO: implement enforcement-specific probes (e.g. LSM or Seccomp integration)
	// For now, it could use the same MonitorSyscallEvent or something else.
	fmt.Println("[Engine] Attaching enforcement-specific probes...")
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
