package micro

import (
	"math"
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

// TestEnforcementSanity: should return EPERM when called under enforcement
// with a policy that doesn't allow getpid (or any syscall not in state 1).
func TestCallAllowed(t *testing.T) {
	_, _, errno := syscall.Syscall(syscall.SYS_CLOSE, uintptr(math.MaxInt32), 0, 0)
	// EBADF = allowed syscall executed normally
	// EPERM = GoSTE blocked it (wrong)
	if errno != syscall.EBADF {
		t.Fatalf("close: expected EBADF, got %v", errno)
	}
}
func TestCallBlocked(t *testing.T) {
	// getpid is NOT in the micro_policy state 1 allowed list (only rt_sigreturn is)
	// Run this after StateTransitionTrigger moves to state 1
	StateTransitionTrigger()
	pid, _, errno := syscall.Syscall(syscall.SYS_GETPID, 0, 0, 0)
	// Under enforcement-errno: should return EPERM, pid=0
	// Without GoSTE: returns real pid, errno=0  
	t.Logf("getpid result: pid=%d errno=%v", pid, errno)
}
