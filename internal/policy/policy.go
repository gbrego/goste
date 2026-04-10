package policy

// State represents a named application state in the security policy.
type State struct {
	// TODO: state name (e.g. "init", "serving", "idle")
	// TODO: set of allowed syscall numbers for this state
}

// Policy holds the full state machine definition for a monitored application.
type Policy struct {
	// TODO: list of states
	// TODO: map of allowed transitions: (fromState, toState) → bool
}

// AllowedSyscalls returns the set of syscalls permitted in a given state.
func (p *Policy) AllowedSyscalls(stateIdx uint32) []uint32 {
	// TODO: look up the allowed syscalls for the given state index
	return nil
}

// IsTransitionAllowed checks whether a goroutine may move between two states.
func (p *Policy) IsTransitionAllowed(from, to uint32) bool {
	// TODO: consult the transition table
	return false
}
