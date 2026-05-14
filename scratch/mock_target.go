package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)

	fmt.Println("Mock target started, waiting for signals...")
	
	select {
	case sig := <-sigs:
		fmt.Printf("Received signal: %s\n", sig)
		fmt.Println("Exiting gracefully...")
		time.Sleep(1 * time.Second)
	case <-time.After(10 * time.Second):
		fmt.Println("Timeout reached")
	}
}
