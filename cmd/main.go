package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"goste/internal/engine"
)

func main() {
	fmt.Println("Starting GoSTE (Go State Trace & Enforce)...")

	// TODO: importing binary from cli
	// if len(os.Args) < 2 {
	// 	fmt.Fprintf(os.Stderr, "Usage: %s <binary-to-trace>\n", os.Args[0])
	// 	os.Exit(1)
	// }
	// targetPath := os.Args[1]

	targetPath := "/home/brego/Documents/Uni/Tesi/sampleTargets/target2"

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Initialize the engine (Attacher/Linker)
	e, err := engine.NewEngine(engine.Config{
		BinaryPath:   targetPath,
		IsTracing:    true,
		StateSymbols: []string{"main.StateA", "main.StateB"},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create engine: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("GoSTE running. Press Ctrl+C to exit.")

	// Start the engine: handles binary loading, probe attachment and event loop.
	// Blocks until ctx is cancelled.
	if err := e.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start engine: %v\n", err)
		os.Exit(1)
	}
	defer e.Stop()

	fmt.Println("\nShutting down GoSTE...")
}
