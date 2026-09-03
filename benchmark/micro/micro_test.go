package micro

import (
	"sync"
	"syscall"
	"testing"
)

//go:noinline
func StateTransitionTrigger() {
	// Dummy function used as a symbol to trigger state transitions in goste
}

func BenchmarkSyscallGetpid(b *testing.B) {
	for i := 0; i < b.N; i++ {
		syscall.Getpid()
	}
}

func BenchmarkStateTransition(b *testing.B) {
	for i := 0; i < b.N; i++ {
		StateTransitionTrigger()
		syscall.Getuid()
	}
}

func BenchmarkGoroutineCreation(b *testing.B) {
	for i := 0; i < b.N; i++ {
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			wg.Done()
		}()
		wg.Wait()
	}
}
