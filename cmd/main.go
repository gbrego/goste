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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	t, err := engine.NewTracer()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create tracer: %v\n", err)
		os.Exit(1)
	}

	if err := t.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start tracer: %v\n", err)
		os.Exit(1)
	}
	defer t.Stop()

	fmt.Println("GoSTE running. Press Ctrl+C to exit.")
	<-ctx.Done()
	fmt.Println("\nShutting down GoSTE...")
}
