package engine

import (
	"context"
	"encoding/binary"
	"fmt"
	"goste/internal/bpf"
	"os"
	"os/exec"
	"syscall"

	"bufio"
	"debug/dwarf"
	"debug/elf"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
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

	TargetTgid     int
	IsChildProcess bool
}

const (
	ActionLog   uint32 = 0
	ActionErrno uint32 = 1
	ActionKill  uint32 = 2

	MaxSyscalls = 512
	MaxStates   = 16

	GoThreadMarker uint32 = 0xFFFFFFFF
)

type Engine struct {

	//Configs passed from main (parsed from cli)
	config Config

	executable    *link.Executable
	executableErr error
	bpfObjects    bpf.GosteObjects

	isPIE            bool
	isGoBinary       bool
	goidOffset       int64
	entryPointOffset uint64
	allmAddr         uint64
	mProcidOffset    int64
	mAlllinkOffset   int64

	// links holds all attached eBPF links (probes, tracepoints) for cleanup.
	links []link.Link
}

type probeTarget struct {
	variants []string
	program  *ebpf.Program
}

// NewEngine creates and initialises a new Engine with the provided configuration.
func NewEngine(cfg Config) (*Engine, error) {
	if cfg.BinaryPath == "" {
		if cfg.TargetTgid != 0 {
			cfg.BinaryPath = fmt.Sprintf("/proc/%d/exe", cfg.TargetTgid)
		}
	}

	return &Engine{
		config: cfg,
	}, nil
}

func (e *Engine) elfManagement() error {
	if e.config.BinaryPath == "" {
		return nil
	}

	f, err := elf.Open(e.config.BinaryPath)
	if err != nil {
		return fmt.Errorf("opening ELF: %w", err)
	}
	defer f.Close()

	e.isGoBinary = e.checkGoBinary(f)

	// modern linux systems compile executables as PIE, which are marked as dynamic shared objects in the elf type
	e.isPIE = (f.Type == elf.ET_DYN)

	if e.config.IsChildProcess {
		e.entryPointOffset, err = e.getEntryPoint(f)
		if err != nil {
			return fmt.Errorf("calculating entry point offset: %w", err)
		}
	}

	if e.isGoBinary {
		d, err := f.DWARF()
		if err != nil {
			fmt.Printf("Warning: extracting DWARF failed: %v (Go-specific tracing might be limited)\n", err)
		} else {
			e.goidOffset, err = e.getGoidOffset(d)
			if err != nil {
				fmt.Printf("Warning: detecting goid offset failed: %v\n", err)
			} else {
				fmt.Printf("Detected goid offset for 'runtime.g.goid': %x\n", e.goidOffset)
			}

			if !e.config.IsChildProcess {
				e.allmAddr, e.mProcidOffset, e.mAlllinkOffset, err = e.getMOffsets(f, d)
				if err != nil {
					fmt.Printf("Warning: extracting M offsets failed: %v\n", err)
				} else {
					fmt.Printf("Detected M offsets: allm=%x, procid=%x, alllink=%x\n", e.allmAddr, e.mProcidOffset, e.mAlllinkOffset)
				}
			}
		}
	}

	return nil
}

func (e *Engine) checkGoBinary(f *elf.File) bool {
	return f.Section(".gopclntab") != nil
}

func (e *Engine) getEntryPoint(f *elf.File) (uint64, error) {
	entryPointVA := f.Entry
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_LOAD {
			if entryPointVA >= prog.Vaddr && entryPointVA < prog.Vaddr+prog.Filesz {
				return entryPointVA - prog.Vaddr + prog.Off, nil
			}
		}
	}
	return 0, fmt.Errorf("cant map virtual address %x to offset", entryPointVA)
}

func (e *Engine) getGoidOffset(d *dwarf.Data) (int64, error) {
	reader := d.Reader()
	for {
		entry, err := reader.Next()
		if err != nil || entry == nil {
			break
		}

		if entry.Tag != dwarf.TagStructType {
			continue
		}

		typ, err := d.Type(entry.Offset)
		if err != nil {
			continue
		}

		st, ok := typ.(*dwarf.StructType)
		if !ok || st.StructName != "runtime.g" {
			continue
		}

		for _, field := range st.Field {
			if field.Name == "goid" {
				return field.ByteOffset, nil
			}
		}
	}
	return 0, fmt.Errorf("goid offset not found")
}

func (e *Engine) getMOffsets(f *elf.File, d *dwarf.Data) (allm uint64, procid int64, alllink int64, err error) {
	symbols, err := f.Symbols()
	if err != nil {
		return 0, 0, 0, fmt.Errorf("reading symbols: %w", err)
	}
	for _, sym := range symbols {
		if sym.Name == "runtime.allm" {
			allm = sym.Value
			break
		}
	}
	if allm == 0 {
		return 0, 0, 0, fmt.Errorf("runtime.allm symbol not found")
	}

	reader := d.Reader()
	for {
		entry, err := reader.Next()
		if err != nil || entry == nil {
			break
		}
		if entry.Tag != dwarf.TagStructType {
			continue
		}
		typ, err := d.Type(entry.Offset)
		if err != nil {
			continue
		}
		st, ok := typ.(*dwarf.StructType)
		if !ok || st.StructName != "runtime.m" {
			continue
		}

		// runtime.m exists only once, after this break anyway
		for _, field := range st.Field {
			switch field.Name {
			case "procid":
				procid = field.ByteOffset
			case "alllink":
				alllink = field.ByteOffset
			}
		}
		break // runtime.m exists only once, no need to continue
	}

	switch {
	case procid == 0 && alllink == 0:
		return allm, 0, 0, fmt.Errorf("procid and alllink not found in runtime.m")
	case procid == 0:
		return allm, 0, 0, fmt.Errorf("procid not found in runtime.m")
	case alllink == 0:
		return allm, 0, 0, fmt.Errorf("alllink not found in runtime.m")
	}

	return allm, procid, alllink, nil
}

// Necessary if binary is in PIE (Position independent executable)
// Finds the base address of the process
func (e *Engine) getProcessBaseAddress() (uint64, error) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", e.config.TargetTgid)
	f, err := os.Open(mapsPath)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, "-")
		if len(parts) > 0 {
			base, err := strconv.ParseUint(parts[0], 16, 64)
			if err != nil {
				return 0, fmt.Errorf("parsing base address: %w", err)
			}
			return base, nil
		}
	}
	return 0, fmt.Errorf("could not find base address in %s", mapsPath)
}

func (e *Engine) readUint64(f *os.File, addr uint64) (uint64, error) {
	buf := make([]byte, 8)
	_, err := f.ReadAt(buf, int64(addr))
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(buf), nil
}

func (e *Engine) scanExistingGoThreads(baseAddr uint64) (map[uint32]bool, error) {
	memPath := fmt.Sprintf("/proc/%d/mem", e.config.TargetTgid)
	memFile, err := os.Open(memPath)
	if err != nil {
		return nil, fmt.Errorf("opening target memory: %w", err)
	}
	defer memFile.Close()

	// If binary is in PIE, we need to add the base address to the offset,
	// PIE implies that the os can load the programm at a random access (ASLR)
	// If not symbols extracted from ELF are allready absolute virtual addresses
	allMAddr := e.allmAddr
	if e.isPIE {
		allMAddr += baseAddr
	}

	// Read pointer to first M
	firstM, err := e.readUint64(memFile, allMAddr)
	if err != nil {
		return nil, fmt.Errorf("reading allm pointer at %x: %w", allMAddr, err)
	}

	goTIDs := make(map[uint32]bool)
	current := firstM
	for current != 0 {
		procid, err := e.readUint64(memFile, current+uint64(e.mProcidOffset))
		if err != nil {
			break
		}
		if procid != 0 {
			goTIDs[uint32(procid)] = true
		}
		current, err = e.readUint64(memFile, current+uint64(e.mAlllinkOffset))
		if err != nil {
			break
		}
	}
	return goTIDs, nil
}

func (e *Engine) applyGoThreadMarkers(tids map[uint32]bool) error {
	for tid := range tids {
		if err := e.markGoThread(tid); err != nil {
			fmt.Printf("Warning: could not mark Go thread %d: %v\n", tid, err)
		}
	}
	return nil
}

func (e *Engine) markGoThread(tid uint32) error {
	// Since kernel 6.9, we must use PIDFD_THREAD to open non-leader threads.
	// This flag is defined as O_EXCL, which is 0x80 on x86_64.
	const PIDFD_THREAD = 0x80
	pidfd, err := unix.PidfdOpen(int(tid), PIDFD_THREAD)
	if err != nil {
		return fmt.Errorf("pidfd_open(%d) with PIDFD_THREAD: %w", tid, err)
	}
	defer unix.Close(pidfd)

	marker := GoThreadMarker
	if err := e.bpfObjects.TaskTraceeMap.Update(int32(pidfd), &marker, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("task_storage update: %w", err)
	}

	fmt.Printf("[Engine] Detected and marked active Go thread: %d\n", tid)
	return nil
}

func (e *Engine) Start(ctx context.Context) error {

	//Load and initialize eBPF maps and programs into the kernel

	if err := e.elfManagement(); err != nil {
		return err
	}

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

	if e.config.BinaryPath != "" {
		e.executable, e.executableErr = link.OpenExecutable(e.config.BinaryPath)
		if e.executableErr != nil {
			fmt.Printf("Warning: opening primary executable %s failed: %v\n", e.config.BinaryPath, e.executableErr)
		}
	}

	if err := e.attachCommonProbes(); err != nil {
		return err
	}

	if e.executable != nil && e.isGoBinary {
		if err := e.attachGoRuntimeProbes(); err != nil {
			return err
		}
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

	if e.config.IsChildProcess {
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
	} else {

		if e.isGoBinary {
			fmt.Printf("Live hooking: scanning for existing Go threads...\n")
			base, err := e.getProcessBaseAddress()
			if err == nil {
				tids, err := e.scanExistingGoThreads(base)
				if err == nil {
					fmt.Printf("Found %d existing Go threads. Marking them in BPF...\n", len(tids))
					e.applyGoThreadMarkers(tids)
				} else {
					fmt.Printf("Warning: failed to scan Go threads: %v\n", err)
				}
			} else {
				fmt.Printf("Warning: failed to get base address: %v\n", err)
			}
		}

		fmt.Printf("Engine ready. Live tracing target\n")
		// Wait for context cancellation
		<-ctx.Done()
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

	// Only set enforcement-related variables when not running as a child process
	if !e.config.IsChildProcess {
		if v, ok := spec.Variables["enforce_action"]; ok {
			if err := v.Set(e.config.EnforceAction); err != nil {
				return fmt.Errorf("setting enforce_action variable: %w", err)
			}
		}

		if v, ok := spec.Variables["targ_tgid"]; ok {
			if err := v.Set(int32(e.config.TargetTgid)); err != nil {
				return fmt.Errorf("setting targ_tgid variable: %w", err)
			}
		}

		if v, ok := spec.Variables["is_child_process"]; ok {
			if err := v.Set(false); err != nil {
				return fmt.Errorf("setting is_child_process variable: %w", err)
			}
		}
	}

	if e.isGoBinary {
		if v, ok := spec.Variables["goid_offset"]; ok {
			if err := v.Set(uint64(e.goidOffset)); err != nil {
				return fmt.Errorf("setting goid_offset variable: %w", err)
			}
		} else {
			return fmt.Errorf("variable 'goid_offset' not found in BPF spec")
		}
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
	up, err := e.executable.Uprobe("", e.bpfObjects.TraceEntryPoint, &link.UprobeOptions{
		Address: e.entryPointOffset,
		Cookie:  uint64(pid),
	})

	if err != nil {
		return fmt.Errorf("attaching entry point uprobe: %w", err)
	}

	e.links = append(e.links, up)
	return nil
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
			if path == "" || path == e.config.BinaryPath {
				exe = e.executable
				if exe == nil {
					if e.executableErr != nil {
						return fmt.Errorf("attaching state transitions: primary executable %s is unavailable: %w", path, e.executableErr)
					}
					return fmt.Errorf("attaching state transitions: primary executable path is not set")
				}
			} else {
				//if path is not the same as the primary executable (ex: external library), open it
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

// DetachProbes removes all eBPF hooks from the kernel, stopping new events.
// It should be called as soon as tracing is no longer needed.
func (e *Engine) DetachProbes() {
	// Close all attached BPF links
	for _, l := range e.links {
		if l != nil {
			l.Close()
		}
	}
	e.links = nil
}

// CloseResources frees the eBPF maps and objects cleanly.
// It is recommended to allow a brief period after DetachProbes before calling this
// (e.g. by performing data collection tasks) to ensure the kernel RCU grace period elapses.
func (e *Engine) CloseResources() {
	// Ensure probes are detached just in case DetachProbes wasn't called explicitly
	e.DetachProbes()
	e.bpfObjects.Close()

	if e.executable != nil {
		// Note: link.Executable doesn't have a Close() method in current cilium/ebpf link API.
	}
}
