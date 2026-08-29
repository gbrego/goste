package engine

import (
	"context"
	"encoding/binary"
	"fmt"
	"goste/internal/bpf"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"syscall"
	"time"

	"bufio"
	"debug/dwarf"
	"debug/elf"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"debug/buildinfo"
	"debug/gosym"
)

type StateSymbol struct {
	Path   string
	Symbol string
}

// Config holds the configuration for the GoSTE Engine.
type Config struct {
	BinaryPath    string
	Args          []string
	IsTracing     bool
	EnforceAction uint32
	StateSymbols  []StateSymbol
	Policy        *Policy

	TargetTgid        int
	IsChildProcess    bool
	SkipPrivilegeDrop bool
	LeastPrivilege    bool
}

const (
	ActionLog   uint32 = 0
	ActionErrno uint32 = 1
	ActionKill  uint32 = 2

	MaxSyscalls = 512
	MaxStates   = 64

	GoThreadMarker uint32 = 0xFFFFFFFF

	// Path to the Linux kernel error injection functions
	ErrorInjectionPath = "/sys/kernel/debug/error_injection/list"
)

type GoVersionOffsets struct {
	GoidOffset     int64
	MProcidOffset  int64
	MAlllinkOffset int64
}

type progSegment struct {
	Vaddr  uint64
	Memsz  uint64
	Filesz uint64
	Off    uint64
}

// hardcoded offsets for different Go versions (amd64)
// this table is used when the binary is stripped
// usually, offsets of Go runtime internal structures
// remain stable within the same minor release
// and change only between major or minor versions.

var goVersionTable = map[string]GoVersionOffsets{
	"go1.20": {GoidOffset: 152, MProcidOffset: 80, MAlllinkOffset: 160},
	"go1.21": {GoidOffset: 152, MProcidOffset: 80, MAlllinkOffset: 168},
	"go1.22": {GoidOffset: 152, MProcidOffset: 80, MAlllinkOffset: 168},
	"go1.23": {GoidOffset: 152, MProcidOffset: 80, MAlllinkOffset: 168},
	"go1.24": {GoidOffset: 152, MProcidOffset: 72, MAlllinkOffset: 328}, //extracted from go 1.24.4
	"go1.25": {GoidOffset: 152, MProcidOffset: 64, MAlllinkOffset: 344}, //extracted from go 1.25.8
	"go1.26": {GoidOffset: 152, MProcidOffset: 64, MAlllinkOffset: 352}, //extracted from go 1.26.2
}

type Engine struct {

	//Configs passed from main (parsed from cli)
	config Config

	executable    *link.Executable
	executableErr error
	bpfObjects    bpf.GosteObjects

	isPIE            bool
	isGoBinary       bool
	isStripped       bool
	goidOffset       int64
	entryPointOffset uint64
	allmAddr         uint64
	mProcidOffset    int64
	mAlllinkOffset   int64

	baseAddr   uint64
	segments   []progSegment
	goSymTable *gosym.Table

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
	e.isStripped = e.checkIfStripped(f)

	for _, prog := range f.Progs {
		if prog.Type == elf.PT_LOAD {
			e.segments = append(e.segments, progSegment{
				Vaddr:  prog.Vaddr,
				Memsz:  prog.Memsz,
				Filesz: prog.Filesz,
				Off:    prog.Off,
			})
		}
	}

	// modern linux systems compile executables as PIE, which are marked as dynamic shared objects in the elf type
	e.isPIE = (f.Type == elf.ET_DYN)

	// If attaching to a live process, retrieve the base address once.
	// This is needed for both stripped (heuristic) and unstripped (symbols/DWARF) PIE binaries.
	if !e.config.IsChildProcess {
		e.baseAddr, _ = e.getProcessBaseAddress()
	} else {
		var err error
		e.entryPointOffset, err = e.virtualToOffset(f.Entry)
		if err != nil {
			return fmt.Errorf("calculating entry point offset: %w", err)
		}
	}

	if e.isGoBinary {
		if e.isStripped {
			fmt.Printf("Warning: binary is stripped, fallback to .gopclntab for symbols and obtaining offsets from static table\n")

			if err := e.parseGoPCLnTab(f); err != nil {
				fmt.Printf("Warning: failed to parse .gopclntab: %v\n", err)
			} else {
				fmt.Printf("Successfully loaded .gopclntab symbols\n")
			}

			version, err := e.getGoVersion()
			if err != nil {
				fmt.Printf("Warning: could not detect Go version: %v\n", err)
			} else {
				fmt.Printf("Detected Go version: %s\n", version)
				shortVersion := version
				parts := strings.Split(version, ".")
				if len(parts) >= 2 {
					shortVersion = parts[0] + "." + parts[1]
				}

				if offsets, ok := goVersionTable[shortVersion]; ok {
					e.goidOffset = offsets.GoidOffset
					e.mProcidOffset = offsets.MProcidOffset
					e.mAlllinkOffset = offsets.MAlllinkOffset

					// If attaching to a live process, try to recover allm via heuristic
					if !e.config.IsChildProcess {
						addr, errHeur := e.findAllmHeuristic(f)
						if errHeur == nil {
							e.allmAddr = addr
							fmt.Printf("Detected allm via heuristic: %x\n", e.allmAddr)
						} else {
							fmt.Printf("Warning: allm heuristic failed: %v\n", errHeur)
						}
					}

					fmt.Printf("Applied offsets for %s: goid=%x, procid=%x, alllink=%x, allm=%x\n",
						shortVersion, e.goidOffset, e.mProcidOffset, e.mAlllinkOffset, e.allmAddr)
				} else {
					fmt.Printf("Warning: no hardcoded offsets for Go version %s. Tracing might fail.\n", shortVersion)
				}
			}

		} else {
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
	}

	return nil
}

func (e *Engine) checkGoBinary(f *elf.File) bool {
	return f.Section(".gopclntab") != nil
}

func (e *Engine) checkIfStripped(f *elf.File) bool {
	return f.Section(".symtab") == nil
}

func (e *Engine) getGoVersion() (string, error) {
	bi, err := buildinfo.ReadFile(e.config.BinaryPath)
	if err != nil {
		return "", err
	}
	return bi.GoVersion, nil
}

func (e *Engine) parseGoPCLnTab(f *elf.File) error {
	pclndat, err := f.Section(".gopclntab").Data()
	if err != nil {
		return fmt.Errorf("reading .gopclntab: %w", err)
	}

	var textStart uint64
	if sect := f.Section(".text"); sect != nil {
		textStart = sect.Addr
	}

	lineTable := gosym.NewLineTable(pclndat, textStart)

	e.goSymTable, err = gosym.NewTable(nil, lineTable)
	if err != nil {
		return fmt.Errorf("creating gosym table: %w", err)
	}
	return nil
}

func (e *Engine) virtualToOffset(va uint64) (uint64, error) {
	for _, seg := range e.segments {
		if va >= seg.Vaddr && va < seg.Vaddr+seg.Memsz {
			return va - seg.Vaddr + seg.Off, nil
		}
	}
	return 0, fmt.Errorf("cant map virtual address %x to offset", va)
}

func (e *Engine) resolveGoSymbol(name string) (uint64, error) {
	if e.goSymTable == nil {
		return 0, fmt.Errorf("gosym table not loaded")
	}

	if fn := e.goSymTable.LookupFunc(name); fn != nil {
		return e.virtualToOffset(fn.Entry)
	}
	return 0, fmt.Errorf("symbol %s not found in .gopclntab", name)
}

func (e *Engine) resolveStateSymbols(symbols []string) ([]uint64, error) {
	if e.goSymTable == nil {
		return nil, fmt.Errorf("gosym table not loaded")
	}

	addresses := make([]uint64, len(symbols))
	for i, sym := range symbols {
		addr, err := e.resolveGoSymbol(sym)
		if err != nil {
			return nil, fmt.Errorf("resolving state symbol %s: %w", sym, err)
		}
		addresses[i] = addr
	}
	return addresses, nil
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

//EXTREME runtime.allm RECOVERY PROCESS
// when live hooking a striped process there is no way to directly access virables, but only functions via .gopclntab
// in recent versions, runtime.allm is allways in .bss (we fall back to checking other sections if necessary)
// tought, it is only not explicitly labelled as such
// it is therefore possible to brute-force check every possible candidate offset:
// if candidateOffset + mProcidOffset matches a real TID then the offset should be correct
// false positives are extremely unlikly

////EXTREME ALLM RECOVERY PROCESS BEGINS////

func (e *Engine) findAllmHeuristic(f *elf.File) (uint64, error) {
	knownTIDs, err := getRealTIDs(e.config.TargetTgid)
	if err != nil {
		return 0, fmt.Errorf("getting real TIDs: %w", err)
	}
	if len(knownTIDs) == 0 {
		return 0, fmt.Errorf("no TIDs found for process %d", e.config.TargetTgid)
	}

	memPath := fmt.Sprintf("/proc/%d/mem", e.config.TargetTgid)
	memFile, err := os.Open(memPath)
	if err != nil {
		return 0, err
	}
	defer memFile.Close()

	// .bss first (in Go 1.20+ allm tends to be there)
	sectionsToScan := []string{".bss", ".noptrdata", ".data", ".noptrbss"}

	maxSize := uint64(0)
	for _, name := range sectionsToScan {
		if sec := f.Section(name); sec != nil && sec.Size > maxSize {
			maxSize = sec.Size
		}
	}
	if maxSize > 64*1024*1024 {
		maxSize = 64 * 1024 * 1024
	}
	buf := make([]byte, maxSize)

	for _, secName := range sectionsToScan {
		sec := f.Section(secName)
		if sec == nil || sec.Size == 0 {
			continue
		}

		sectionStart := sec.Addr
		sectionSize := min(sec.Size, uint64(64*1024*1024))
		if e.isPIE {
			sectionStart += e.baseAddr
		}

		readBuf := buf[:sectionSize]
		if _, err := memFile.ReadAt(readBuf, int64(sectionStart)); err != nil {
			fmt.Printf("Warning: failed to read section %s: %v\n", secName, err)
			continue
		}

		for offset := uint64(0); offset+8 <= sectionSize; offset += 8 {
			firstM := binary.LittleEndian.Uint64(readBuf[offset : offset+8])
			if firstM == 0 || firstM < 0x10000 || firstM > 0x800000000000 {
				continue
			}

			if e.validateAllmCandidate(memFile, firstM, knownTIDs) {
				addr := sectionStart + offset
				fmt.Printf("[Engine] Found allm in %s at %x\n", secName, addr)
				if e.isPIE {
					addr -= e.baseAddr
				}
				return addr, nil
			}
		}
	}

	return 0, fmt.Errorf("allm not found via heuristic in any section")
}

// simply checks if candidate is valid by confrointing extracted TIDs with process TIDs
// odds of false positive are now ^3 (maxWalk = 3), which means i's virtually impossible to fall for one
func (e *Engine) validateAllmCandidate(memFile *os.File, firstM uint64, knownTIDs map[uint32]bool) bool {
	const maxWalk = 3
	current := firstM
	matchedAtLeastOne := false

	for i := 0; i < maxWalk && current != 0; i++ {
		if current < 0x10000 || current > 0x800000000000 {
			return false
		}
		procid, err := e.readUint64(memFile, current+uint64(e.mProcidOffset))
		if err != nil {
			return false
		}
		if procid != 0 {
			if !knownTIDs[uint32(procid)] {
				return false // false positive
			}
			matchedAtLeastOne = true
		}
		next, err := e.readUint64(memFile, current+uint64(e.mAlllinkOffset))
		if err != nil {
			return false
		}
		current = next
	}
	return matchedAtLeastOne // refuses candidates with all procid == 0
}

func getRealTIDs(pid int) (map[uint32]bool, error) {
	taskPath := fmt.Sprintf("/proc/%d/task", pid)
	entries, err := os.ReadDir(taskPath)
	if err != nil {
		return nil, err
	}
	tids := make(map[uint32]bool, len(entries))
	for _, e := range entries {
		tid, err := strconv.ParseUint(e.Name(), 10, 32)
		if err == nil {
			tids[uint32(tid)] = true
		}
	}
	return tids, nil
}

func getNoptrdataRange(f *elf.File) (start, size uint64, err error) {
	sec := f.Section(".noptrdata")
	if sec == nil {
		return 0, 0, fmt.Errorf(".noptrdata section not found")
	}
	return sec.Addr, sec.Size, nil
}

////EXTREME ALLM RECOVERY PROCESS ENDS////

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
	if allMAddr == 0 {
		return nil, fmt.Errorf("allm address is 0, cannot scan threads")
	}
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
			// e.baseAddr is already calculated in elfManagement
			tids, err := e.scanExistingGoThreads(e.baseAddr)
			if err == nil {
				fmt.Printf("Found %d existing Go threads. Marking them in BPF...\n", len(tids))
				e.applyGoThreadMarkers(tids)
			} else {
				fmt.Printf("Warning: failed to scan Go threads: %v\n", err)
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

	// Set enforcement-related variables
	if v, ok := spec.Variables["enforce_action"]; ok {
		if err := v.Set(e.config.EnforceAction); err != nil {
			return fmt.Errorf("setting enforce_action variable: %w", err)
		}
	}

	// Only set TGID-related filters when not running as a child process (PID-based attach)
	if !e.config.IsChildProcess {
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

		// Disable basic state transition program if only 1 state
		if numStates == 1 {
			delete(spec.Programs, "trigger_state_transition")
		}
	}

	// Disable child process tracing if we are attaching to a live process
	if !e.config.IsChildProcess {
		delete(spec.Programs, "trace_entry_point")
	}

	// Disable unnecessary programs based on the operational mode
	if e.config.IsTracing || (!e.config.IsTracing && e.config.EnforceAction == ActionLog) {
		delete(spec.Programs, "override_syscall_filter")
	} else {
		delete(spec.Programs, "monitor_syscall_event")
	}

	//using NewCollection instead of LoadAndAssign to handle deleted programs
	//there is no elegant way to do this currently with bpf2go, manual import is needed
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
	if err != nil {
		return fmt.Errorf("loading BPF collection: %w", err)
	}

	// Manually assign maps
	e.bpfObjects.GoroutineTraceeMap = coll.Maps["goroutine_tracee_map"]
	e.bpfObjects.PendingGoroutines = coll.Maps["pending_goroutines"]
	e.bpfObjects.StateMap = coll.Maps["state_map"]
	e.bpfObjects.TaskTraceeMap = coll.Maps["task_tracee_map"]

	// Manually assign programs (missing ones will safely be nil)
	e.bpfObjects.CompleteTraceNewGoroutine = coll.Programs["complete_trace_new_goroutine"]
	e.bpfObjects.InheritStateInfo = coll.Programs["inherit_state_info"]
	e.bpfObjects.MarkGoThread = coll.Programs["mark_go_thread"]
	e.bpfObjects.MonitorSyscallEvent = coll.Programs["monitor_syscall_event"]
	e.bpfObjects.OverrideSyscallFilter = coll.Programs["override_syscall_filter"]
	e.bpfObjects.RemoveExitingGoroutine = coll.Programs["remove_exiting_goroutine"]
	e.bpfObjects.TraceEntryPoint = coll.Programs["trace_entry_point"]
	e.bpfObjects.TraceNewGoroutine = coll.Programs["trace_new_goroutine"]
	e.bpfObjects.TriggerStateTransition = coll.Programs["trigger_state_transition"]

	return nil
}

// This function is to be skipped when attaching to a live process (PID provided by user)
func (e *Engine) runTarget(ctx context.Context) (int, <-chan error, error) {
	cmd := exec.CommandContext(ctx, e.config.BinaryPath, e.config.Args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	cmd.Cancel = func() error {
		fmt.Printf("\n[Engine] Propagating SIGTERM to child process (PID %d)...\n", cmd.Process.Pid)
		// Try graceful termination first
		err := cmd.Process.Signal(syscall.SIGTERM)

		// Schedule a hard kill if it doesn't exit within a timeout
		go func() {
			time.Sleep(5 * time.Second)
			if err := cmd.Process.Signal(syscall.Signal(0)); err == nil {
				fmt.Printf("[Engine] Child process (PID %d) still alive after 5s, sending SIGKILL\n", cmd.Process.Pid)
				cmd.Process.Kill()
			}
		}()
		return err
	}

	// CONCEPT: ask kernel to stop task right after syscall 'exec'
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Ptrace: true,
	}

	// drop root privileges for target application
	// goste must be run as root to use eBPF, however the potentially malicius target must not inherit sudo privileges
	if !e.config.SkipPrivilegeDrop {
		if sudoUID := os.Getenv("SUDO_UID"); sudoUID != "" {
			if sudoGID := os.Getenv("SUDO_GID"); sudoGID != "" {
				uid, errUID := strconv.Atoi(sudoUID)
				gid, errGID := strconv.Atoi(sudoGID)
				if errUID == nil && errGID == nil {
					cmd.SysProcAttr.Credential = &syscall.Credential{
						Uid: uint32(uid),
						Gid: uint32(gid),
					}
					fmt.Printf("[Engine] Dropping target process privileges to uid=%d gid=%d\n", uid, gid)

					// Restore HOME and USER environment variables for the dropped privilege user
					if u, err := user.LookupId(sudoUID); err == nil {
						cmd.Env = os.Environ()
						for i, env := range cmd.Env {
							if strings.HasPrefix(env, "HOME=") {
								cmd.Env[i] = "HOME=" + u.HomeDir
							} else if strings.HasPrefix(env, "USER=") {
								cmd.Env[i] = "USER=" + u.Username
							}
						}
					}
				}
			}
		}
	} else {
		fmt.Printf("[Engine] Skipping privilege drop for target process.\n")
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
		var err error
		var up link.Link

		if e.isStripped && e.goSymTable != nil {
			addr, resolveErr := e.resolveGoSymbol(sym)
			if resolveErr == nil {
				up, err = e.executable.Uprobe(sym, probe.program, &link.UprobeOptions{Address: addr})
			} else {
				err = resolveErr
			}
		} else {
			up, err = e.executable.Uprobe(sym, probe.program, nil)
		}

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

			var um link.Link
			if e.isStripped && e.goSymTable != nil && (path == "" || path == e.config.BinaryPath) {
				addresses, err := e.resolveStateSymbols(symbols)
				if err != nil {
					return fmt.Errorf("resolving state symbols for stripped binary: %w", err)
				}
				// When using Addresses, symbols argument must be nil
				um, err = exe.UprobeMulti(nil, e.bpfObjects.TriggerStateTransition, &link.UprobeMultiOptions{
					Addresses: addresses,
					Cookies:   cookies,
				})
			} else {
				um, err = exe.UprobeMulti(symbols, e.bpfObjects.TriggerStateTransition, &link.UprobeMultiOptions{
					Cookies: cookies,
				})
			}

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
	fmt.Println("[Engine] Attaching enforcement-specific probes (OverrideSyscallFilter)...")

	// Read available filter functions to safely determine which syscalls can be hooked on this host
	file, err := os.Open(ErrorInjectionPath)
	if err != nil {
		return fmt.Errorf("failed to open error_injection/list: %w (is debugfs mounted?)", err)
	}
	defer file.Close()
	var symbols []string
	var cookies []uint64
	seen := make(map[string]bool)
	prefix := "__x64_sys_"
	if runtime.GOARCH == "arm64" {
		// even though currently goste only works on amd64
		prefix = "__arm64_sys_"
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// the file format is: <function_name> [<module>]\n (es: __x64_sys_read [kernel])
		// Fields are used to extract only the first protected token
		parts := strings.Fields(scanner.Text())
		if len(parts) == 0 {
			continue
		}
		sym := parts[0]
		if strings.HasPrefix(sym, prefix) {
			name := strings.TrimPrefix(sym, prefix)
			if id, ok := GeneratedSyscallsByName[name]; ok {
				if !seen[sym] {
					symbols = append(symbols, sym)
					cookies = append(cookies, uint64(id))
					seen[sym] = true
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to read filter functions: %w", err)
	}

	if len(symbols) == 0 {
		return fmt.Errorf("no matching syscalls found in available_filter_functions with prefix %s", prefix)
	}

	km, err := link.KprobeMulti(e.bpfObjects.OverrideSyscallFilter, link.KprobeMultiOptions{
		Symbols: symbols,
		Cookies: cookies,
	})
	if err != nil {
		return fmt.Errorf("attaching kprobe.multi for syscall enforcement: %w", err)
	}

	e.links = append(e.links, km)
	fmt.Printf("[Engine] Successfully hooked %d syscalls for enforcement.\n", len(symbols))
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
