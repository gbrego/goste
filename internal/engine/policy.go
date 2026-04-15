package engine

import (
	"encoding/json"
	"fmt"
	"goste/internal/bpf"
	"os"
	"sort"
)

//go:generate go run ../../scripts/gen_syscalls.go

// Policy represents the final security file generated or loaded by GoSTE.
type Policy struct {
	Binary string  `json:"binary"`
	States []State `json:"states"`
}

// State represents a node in the application state graph.
type State struct {
	ID       uint32   `json:"id"`
	Probe    *Probe   `json:"probe,omitempty"`
	Syscalls []string `json:"syscalls"`
	Next     []uint32 `json:"next"`
}

// Probe defines where the trigger for the state change is injected.
type Probe struct {
	Symbol string `json:"symbol,omitempty"`
	Offset string `json:"offset,omitempty"`
	Path   string `json:"path,omitempty"`
}

// CollectPolicy retrieves the state_map from BPF, processes it with back-propagation,
// and returns a finalized Policy object.
func (e *Engine) CollectPolicy() (*Policy, error) {
	stateMap := make(map[uint32]bpf.GosteAppState)
	var val bpf.GosteAppState

	// Read all entries from the StateMap
	// Note: state_map is an array of size len(StateSymbols) + 1
	numStates := uint32(len(e.config.StateSymbols) + 1)
	for i := uint32(0); i < numStates; i++ {
		if err := e.bpfObjects.StateMap.Lookup(i, &val); err == nil {
			stateMap[i] = val
		}
	}

	// Run back-propagation algorithm
	finalizedSyscalls, nextStates := flowBasedBackpropagation(stateMap, numStates)

	policy := &Policy{
		Binary: e.config.BinaryPath,
		States: make([]State, 0, numStates),
	}

	for i := uint32(0); i < numStates; i++ {
		state := State{
			ID:       i,
			Syscalls: syscallsToNames(finalizedSyscalls[i]),
			Next:     nextStates[i],
		}

		// Add probe info if applicable
		if i > 0 && i-1 < uint32(len(e.config.StateSymbols)) {
			state.Probe = &Probe{
				Symbol: e.config.StateSymbols[i-1],
			}
		}

		policy.States = append(policy.States, state)
	}

	return policy, nil
}

// flowBasedBackpropagation implements Kosaraju's algorithm for SCCs and bitwise-OR propagation.
func flowBasedBackpropagation(stateMap map[uint32]bpf.GosteAppState, numStates uint32) (map[uint32][]bool, map[uint32][]uint32) {
	// 1. Build adjacency list and transposed graph
	adj := make([][]uint32, numStates)
	revAdj := make([][]uint32, numStates)
	syscalls := make(map[uint32][]bool)

	for i := uint32(0); i < numStates; i++ {
		appState := stateMap[i]

		// Fill initial syscalls
		sSet := make([]bool, 512)
		for j := 0; j < 512; j++ {
			if appState.Syscalls[j] != 0 {
				sSet[j] = true
			}
		}
		syscalls[i] = sSet

		// Fill edges
		for j := uint32(0); j < 16; j++ {
			if appState.NextState[j] != 0 {
				adj[i] = append(adj[i], j)
				revAdj[j] = append(revAdj[j], i)
			}
		}
	}

	// 2. Kosaraju's Phase 1: DFS for finish times
	visited := make([]bool, numStates)
	stack := make([]uint32, 0)
	var dfs1 func(uint32)
	dfs1 = func(u uint32) {
		visited[u] = true
		for _, v := range adj[u] {
			if !visited[v] {
				dfs1(v)
			}
		}
		stack = append(stack, u)
	}
	for i := uint32(0); i < numStates; i++ {
		if !visited[i] {
			dfs1(i)
		}
	}

	// 3. Kosaraju's Phase 2: DFS on transposed graph for SCCs
	visited = make([]bool, numStates)
	sccs := make([][]uint32, 0)
	var currentSCC []uint32
	var dfs2 func(uint32)
	dfs2 = func(u uint32) {
		visited[u] = true
		currentSCC = append(currentSCC, u)
		for _, v := range revAdj[u] {
			if !visited[v] {
				dfs2(v)
			}
		}
	}

	nodeToSCC := make([]int, numStates)
	for i := len(stack) - 1; i >= 0; i-- {
		u := stack[i]
		if !visited[u] {
			currentSCC = make([]uint32, 0)
			dfs2(u)
			sccIdx := len(sccs)
			for _, node := range currentSCC {
				nodeToSCC[node] = sccIdx
			}
			sccs = append(sccs, currentSCC)
		}
	}

	// 4. Merge syscalls within each SCC
	sccSyscalls := make([][]bool, len(sccs))
	for i, scc := range sccs {
		merged := make([]bool, 512)
		for _, node := range scc {
			for j := 0; j < 512; j++ {
				if syscalls[node][j] {
					merged[j] = true
				}
			}
		}
		sccSyscalls[i] = merged
	}

	// 5. Build condensation graph (DAG of SCCs)
	sccAdj := make([]map[int]bool, len(sccs))
	for i := range sccAdj {
		sccAdj[i] = make(map[int]bool)
	}
	for u := uint32(0); u < numStates; u++ {
		uSCC := nodeToSCC[u]
		for _, v := range adj[u] {
			vSCC := nodeToSCC[v]
			if uSCC != vSCC {
				sccAdj[uSCC][vSCC] = true
			}
		}
	}

	// 6. Back-propagation across the condensation graph
	// We need to process SCCs in reverse topological order.
	// In Kosaraju's, the order in which we find SCCs (Phase 2) is a topological sort of the condensation graph.
	// So we process from the last found SCC to the first.
	for i := len(sccs) - 1; i >= 0; i-- {
		for neighborSCC := range sccAdj[i] {
			// Propagate from neighbor to current: Perm(i) |= Perm(neighbor)
			for j := 0; j < 512; j++ {
				if sccSyscalls[neighborSCC][j] {
					sccSyscalls[i][j] = true
				}
			}
		}
	}

	// 7. Map back to original nodes
	finalizedSyscalls := make(map[uint32][]bool)
	nextStates := make(map[uint32][]uint32)
	for u := uint32(0); u < numStates; u++ {
		finalizedSyscalls[u] = sccSyscalls[nodeToSCC[u]]
		nextStates[u] = adj[u]
	}

	return finalizedSyscalls, nextStates
}

func syscallsToNames(bitmap []bool) []string {
	var names []string
	for i, allowed := range bitmap {
		if allowed {
			if name, ok := GeneratedSyscalls[i]; ok {
				names = append(names, name)
			} else {
				names = append(names, fmt.Sprintf("syscall_%d", i))
			}
		}
	}
	sort.Strings(names)
	return names
}

// WritePolicyToFile writes the policy object to a JSON file.
func (p *Policy) WritePolicyToFile(path string) error {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// PrintPolicy prints the policy object to stdout in a human-readable format.
func (p *Policy) PrintPolicy() {
	fmt.Printf("\n--- Finalized Policy Graph ---\n")
	fmt.Printf("Binary: %s\n", p.Binary)
	for _, s := range p.States {
		fmt.Printf("\nState ID: %d", s.ID)
		if s.Probe != nil {
			fmt.Printf(" (Probe: %s)", s.Probe.Symbol)
		}
		fmt.Printf("\n  Allowed Syscalls (%d):\n", len(s.Syscalls))
		for i, name := range s.Syscalls {
			fmt.Printf("    %-15s", name)
			if (i+1)%4 == 0 {
				fmt.Println()
			}
		}
		if len(s.Syscalls)%4 != 0 {
			fmt.Println()
		}
		fmt.Printf("  Next States: %v\n", s.Next)
	}
	fmt.Printf("\n--- End of Policy ---\n")
}
