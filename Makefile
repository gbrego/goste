.PHONY: all generate build run clean

TARGET     := goste
BPF_DIR    := bpf
GO_BPF_DIR := internal/bpf

# Architecture detection (mirrors libbpf-bootstrap / SysComb convention)
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
                         | sed 's/arm.*/arm/' \
                         | sed 's/aarch64/arm64/' \
                         | sed 's/ppc64le/powerpc/' \
                         | sed 's/mips.*/mips/' \
                         | sed 's/riscv64/riscv/')

# Tools — override on the command line if needed (e.g. make CLANG=clang-17)
CLANG   ?= clang
BPFTOOL ?= bpftool

# Portable include detection: ask Clang itself where its system headers live.
# Works on any distro / arch without any hardcoded paths.
CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

# vmlinux.h is committed per-arch so no bpftool needed for normal builds.
VMLINUX := $(BPF_DIR)/vmlinux/$(ARCH)/vmlinux.h

.DEFAULT_GOAL := all

## all: generate eBPF Go bindings and build the binary
all: generate build

## generate: compile goste.bpf.c → Go bindings using bpf2go
generate:
	cd $(GO_BPF_DIR) && GOPACKAGE=bpf go run github.com/cilium/ebpf/cmd/bpf2go \
		-cc $(CLANG) Goste ../../$(BPF_DIR)/goste.bpf.c \
		-- -I../../$(BPF_DIR) -I../../$(dir $(VMLINUX)) $(CLANG_BPF_SYS_INCLUDES)

## build: compile the Go user-space binary
build:
	go build -o $(TARGET) ./cmd

## run: build and run (eBPF requires root)
run: build
	sudo ./$(TARGET)

## vmlinux: regenerate vmlinux.h for the current arch from the running kernel.
##          Only needed when updating to a new kernel. Commit the result.
vmlinux:
	mkdir -p $(dir $(VMLINUX))
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)
	@echo "Done. Commit $(VMLINUX) to the repository."

## clean: remove all build and generated artifacts
clean:
	rm -f $(TARGET)
	rm -f $(GO_BPF_DIR)/*_bpfel.*
	rm -f $(GO_BPF_DIR)/*_bpfeb.*

## help: list available targets
help:
	@grep "^##" Makefile | sed 's/## /  /'
