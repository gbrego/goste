package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"goste/internal/engine"
)

func main() {
	fmt.Println("Starting GoSTE (Go State Trace & Enforce)...")

	outputFlag := flag.String("o", "", "Path to the output JSON policy file")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <binary-to-trace>\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	targetPath := flag.Arg(0)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Initialize the engine (Attacher/Linker)
	e, err := engine.NewEngine(engine.Config{
		BinaryPath:   targetPath,
		IsTracing:    true,
		// Example state symbols: for a real use case, these might be loaded from a config or detected
		StateSymbols: []string{"main.StateA", "main.StateB"},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create engine: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("GoSTE running on %s. Press Ctrl+C to stop tracing and collect policy.\n", targetPath)

	// Start the engine: handles binary loading, probe attachment and event loop.
	// Blocks until ctx is cancelled or target exits.
	if err := e.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start engine: %v\n", err)
		os.Exit(1)
	}
	defer e.Stop()

	fmt.Println("\nCollecting and finalizing policy...")

	policy, err := e.CollectPolicy()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to collect policy: %v\n", err)
		os.Exit(1)
	}

	if *outputFlag != "" {
		if err := policy.WritePolicyToFile(*outputFlag); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write policy to %s: %v\n", *outputFlag, err)
		} else {
			fmt.Printf("Policy successfully saved to %s\n", *outputFlag)
		}
	} else {
		policy.PrintPolicy()
	}

	fmt.Println("Shutting down GoSTE...")
}
