// main.go
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"goste/internal/bpf"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// tabella syscall number → nome
// ne mettiamo solo alcune comuni per semplicità
var syscallNames = map[uint32]string{
	0:   "read",
	1:   "write",
	2:   "open",
	3:   "close",
	4:   "stat",
	59:  "execve",
	60:  "exit",
	231: "exit_group",
}

func main() {
	fmt.Println("Avvio syscall tracer... (Ctrl+C per uscire)")

	// setup Ctrl+C — crea un context che si cancella al segnale
	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	// lancia il tracer
	if err := runTracer(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Errore: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\nTracer fermato.")
}

func runTracer(ctx context.Context) error {

	// 1. carica gli oggetti BPF nel kernel
	//    (MonitorObjects e LoadMonitorObjects sono generati da bpf2go)
	objs := bpf.GosteObjects{}
	if err := bpf.LoadGosteObjects(&objs, nil); err != nil {
		return fmt.Errorf("caricamento oggetti BPF fallito: %w", err)
	}
	defer objs.Close()

	// 2. attacca il programma BPF al tracepoint sys_enter
	//    da ora ogni syscall triggera monitor_syscall() nel kernel
	tp, err := link.Tracepoint("raw_syscalls", "sys_enter", objs.MonitorSyscall, nil)
	if err != nil {
		return fmt.Errorf("attacco tracepoint fallito: %w", err)
	}
	defer tp.Close()

	// 3. apri la ring buffer per ricevere gli eventi dal kernel
	rb, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("apertura ringbuf fallita: %w", err)
	}
	defer rb.Close()

	fmt.Println("In ascolto... ogni riga è una syscall.")
	fmt.Printf("%-8s %-20s %-6s %s\n", "PID", "PROCESSO", "NR", "SYSCALL")
	fmt.Println("─────────────────────────────────────────")

	// 4. canale per gli eventi grezzi
	eventi := make(chan []byte, 100)

	// 5. goroutine dedicata alla lettura dalla ringbuf
	//    rb.Read() è bloccante — gira in parallelo nel suo thread
	go func() {
		for {
			record, err := rb.Read()
			if err != nil {
				return // ringbuf chiusa (ctx cancellato)
			}
			eventi <- record.RawSample
		}
	}()

	// 6. loop principale — processa eventi o aspetta Ctrl+C
	for {
		select {

		case <-ctx.Done():
			// Ctrl+C → esci pulitamente
			// i defer chiuderanno ringbuf, tracepoint e oggetti BPF
			return nil

		case raw := <-eventi:
			// deserializza i bytes grezzi nella struct Go
			var event bpf.GosteEvent
			if err := binary.Read(
				bytes.NewReader(raw),
				binary.NativeEndian, // endianness della macchina corrente
				&event,
			); err != nil {
				continue // evento malformato, salta
			}

			// converti il nome del processo da [16]int8 a string
			comm := int8SliceToString(event.Comm[:])

			// cerca il nome della syscall nella tabella
			syscallName, ok := syscallNames[event.SyscallNr]
			if !ok {
				syscallName = fmt.Sprintf("syscall_%d", event.SyscallNr)
			}

			fmt.Printf("%-8d %-20s %-6d %s\n",
				event.Pid,
				comm,
				event.SyscallNr,
				syscallName,
			)
		}
	}
}

// converte [16]int8 (come arriva dal kernel) in una stringa Go leggibile
func int8SliceToString(s []int8) string {
	b := make([]byte, len(s))
	for i, v := range s {
		if v == 0 {
			break // stringa terminata da null come in C
		}
		b[i] = byte(v)
	}
	return string(bytes.TrimRight(b, "\x00"))
}
