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

	numStates := uint32(len(e.config.StateSymbols) + 1)
	for i := uint32(0); i < numStates; i++ {
		if err := e.bpfObjects.StateMap.Lookup(i, &val); err == nil {
			stateMap[i] = val
		}
	}

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
		if i > 0 && i-1 < uint32(len(e.config.StateSymbols)) {
			state.Probe = &Probe{Symbol: e.config.StateSymbols[i-1]}
		}
		policy.States = append(policy.States, state)
	}

	return policy, nil
}

// flowBasedBackpropagation implements a leaner version of Kosaraju's algorithm 
// with in-place back-propagation, mirroring SysComb's logic.
func flowBasedBackpropagation(stateMap map[uint32]bpf.GosteAppState, num uint32) (map[uint32][]bool, [][]uint32) {
	adj := make([][]uint32, num)
	rev := make([][]uint32, num)
	perms := make([][]bool, num)

	for i := uint32(0); i < num; i++ {
		s := stateMap[i]
		perms[i] = make([]bool, 512)
		for j := 0; j < 512; j++ {
			if s.Syscalls[j] != 0 { perms[i][j] = true }
		}
		for j := uint32(0); j < 16; j++ {
			if s.NextState[j] != 0 {
				adj[i] = append(adj[i], j)
				rev[j] = append(rev[j], i)
			}
		}
	}

	// Phase 1: DFS for finish times
	visited := make([]bool, num)
	stack := make([]uint32, 0, num)
	var dfs1 func(uint32)
	dfs1 = func(u uint32) {
		visited[u] = true
		for _, v := range adj[u] {
			if !visited[v] { dfs1(v) }
		}
		stack = append(stack, u)
	}
	for i := uint32(0); i < num; i++ {
		if !visited[i] { dfs1(i) }
	}

	// Phase 2: DFS on transposed graph + direct propagation
	visited = make([]bool, num)
	roots := make([]uint32, num)
	finalPerms := make(map[uint32][]bool)

	for i := int(num) - 1; i >= 0; i-- {
		u := stack[i]
		if !visited[u] {
			component := make([]uint32, 0)
			var dfs2 func(uint32)
			dfs2 = func(curr uint32) {
				visited[curr] = true
				component = append(component, curr)
				for _, prev := range rev[curr] {
					if !visited[prev] { dfs2(prev) }
				}
			}
			dfs2(u)

			// Merge and back-propagate
			root := component[0]
			merged := make([]bool, 512)
			for _, node := range component {
				roots[node] = root
				for j := 0; j < 512; j++ {
					if perms[node][j] { merged[j] = true }
				}
			}

			// Apply merged profile to SCC members
			for _, node := range component { perms[node] = merged }

			// Back-propagate to all states that transition to this SCC
			for _, node := range component {
				for prev := uint32(0); prev < num; prev++ {
					// If there is an edge prev -> node AND prev is not in the same SCC
					isEdge := false
					for _, next := range adj[prev] {
						if next == node { isEdge = true; break }
					}
					if isEdge && roots[prev] != root {
						for j := 0; j < 512; j++ {
							if merged[j] { perms[prev][j] = true }
						}
					}
				}
			}
		}
	}

	for i := uint32(0); i < num; i++ { finalPerms[i] = perms[i] }
	return finalPerms, adj
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
			if (i+1)%4 == 0 { fmt.Println() }
		}
		if len(s.Syscalls)%4 != 0 { fmt.Println() }
		fmt.Printf("  Next States: %v\n", s.Next)
	}
	fmt.Printf("\n--- End of Policy ---\n")
}
