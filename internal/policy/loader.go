package policy

// LoadFromFile reads a policy configuration file (e.g. JSON or YAML)
// and returns a populated Policy ready to be programmed into the eBPF maps.
func LoadFromFile(path string) (*Policy, error) {
	// TODO: open and parse the config file
	// TODO: validate states and transitions
	// TODO: return populated Policy
	return &Policy{}, nil
}
