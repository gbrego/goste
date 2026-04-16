package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"goste/internal/engine"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	subcommand := os.Args[1]
	switch subcommand {
	case "trace":
		runTrace()
	case "enforce":
		runEnforce()
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown subcommand: %s\n", subcommand)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: goste <subcommand> [options]")
	fmt.Println("\nSubcommands:")
	fmt.Println("  trace   Trace application states and syscalls to generate a policy")
	fmt.Println("  enforce Enforce a previously generated security policy")
	fmt.Println("\nRun 'goste <subcommand> -h' for more details on each subcommand.")
}

func runTrace() {
	traceCmd := flag.NewFlagSet("trace", flag.ExitOnError)
	outputFlag := traceCmd.String("o", "", "Path to the output JSON policy file")
	symbolsFlag := traceCmd.String("s", "", "Comma-separated list of symbols to trace for state transitions")

	traceCmd.Parse(os.Args[2:])

	if traceCmd.NArg() < 1 {
		fmt.Println("Usage: goste trace [options] <binary-to-trace>")
		traceCmd.PrintDefaults()
		os.Exit(1)
	}

	targetPath := traceCmd.Arg(0)
	var stateSymbols []string
	if *symbolsFlag != "" {
		stateSymbols = strings.Split(*symbolsFlag, ",")
		for i := range stateSymbols {
			stateSymbols[i] = strings.TrimSpace(stateSymbols[i])
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	e, err := engine.NewEngine(engine.Config{
		BinaryPath:   targetPath,
		IsTracing:    true,
		StateSymbols: stateSymbols,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create engine: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("GoSTE Tracing: %s. Symbols: %v\n", targetPath, stateSymbols)
	if err := e.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start engine: %v\n", err)
		os.Exit(1)
	}
	defer e.Stop()

	policy, err := e.CollectPolicy()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to collect policy: %v\n", err)
		os.Exit(1)
	}

	if *outputFlag != "" {
		if err := policy.WritePolicyToFile(*outputFlag); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write policy to %s: %v\n", *outputFlag, err)
		} else {
			fmt.Printf("Policy saved to %s\n", *outputFlag)
		}
	} else {
		policy.PrintPolicy()
	}
}

func runEnforce() {
	enforceCmd := flag.NewFlagSet("enforce", flag.ExitOnError)
	actionFlag := enforceCmd.String("a", "errno", "Action on violation: log, errno, kill-process")

	enforceCmd.Parse(os.Args[2:])

	// Required: policy path and target binary
	if enforceCmd.NArg() < 2 {
		fmt.Println("Usage: goste enforce -a <action> <policy.json> <binary-to-trace>")
		enforceCmd.PrintDefaults()
		os.Exit(1)
	}

	policyPath := enforceCmd.Arg(0)
	targetPath := enforceCmd.Arg(1)

	actionMap := map[string]uint32{
		"log":          engine.ActionLog,
		"errno":        engine.ActionErrno,
		"kill-process": engine.ActionKill,
	}
	actionID, ok := actionMap[*actionFlag]
	if !ok {
		fmt.Fprintf(os.Stderr, "Invalid action: %s. Valid: log, errno, kill-process\n", *actionFlag)
		os.Exit(1)
	}

	policy, err := engine.LoadPolicy(policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load policy: %v\n", err)
		os.Exit(1)
	}

	stateSymbols := policy.GetStateSymbols()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	e, err := engine.NewEngine(engine.Config{
		BinaryPath:    targetPath,
		IsTracing:     false,
		EnforceAction: actionID,
		Policy:        policy,
		StateSymbols:  stateSymbols,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create engine: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("GoSTE Enforcement: %s using policy %s (Action: %s)\n", targetPath, policyPath, *actionFlag)
	if err := e.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start engine: %v\n", err)
		os.Exit(1)
	}
	defer e.Stop()
}
