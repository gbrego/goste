package micro

import (
	"sync"
	"syscall"
	"testing"
	"time"
)

//go:noinline
func StateTransitionTrigger() {
	// Dummy function used as a symbol to trigger state transitions in goste
}

func BenchmarkSyscallClose(b *testing.B) {
	for i := 0; i < b.N; i++ {
		syscall.Close(-1)
	}
}

func BenchmarkStateTransition(b *testing.B) {
	for i := 0; i < b.N; i++ {
		StateTransitionTrigger()
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

func BenchmarkParallelSyscallClose(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			syscall.Close(-1)
		}
	})
}

func BenchmarkParallelStateTransition(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			StateTransitionTrigger()
		}
	})
}

func TestSleep(t *testing.T) {
	time.Sleep(5 * time.Minute)
}

func TestShortSleep(t *testing.T) {
	// 1s is enough to capture all Go runtime syscalls for policy generation.
	time.Sleep(1 * time.Second)
}
