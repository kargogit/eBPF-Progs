# Makefile for eBPF socket filter example
#
# Build process overview:
# 1. Compile kernel-space eBPF code → BPF bytecode object (socket_filter_kern.o)
#    - Uses Clang with -target bpf
#    - No linking step — the output is relocatable ELF containing BPF instructions
# 2. Generate libbpf skeleton header (socket_filter_kern.skel.h)
#    - bpftool extracts program/map information for easy user-space access
# 3. Compile user-space loader program against libbpf
#
# Common tools:
# - clang (with LLVM BPF backend)
# - bpftool (for skeleton generation)
# - libbpf (user-space library)

CLANG ?= clang

# Object files (BPF bytecode)
OBJS = socket_filter_kern.o

# Final user-space binary
USER_TARGETS = socket_filter_user

.PHONY: all clean skeleton

# Default target: build user program and skeleton
all: $(USER_TARGETS) skeleton

# Compile eBPF kernel program to BPF object file
# Flags explained:
# -O2                  → optimization level required for good BPF code
# -target bpf          → generate BPF bytecode
# -D__TARGET_ARCH_x86  → helps CO-RE (Compile Once – Run Everywhere) relocations
# -g                   → include debug info (useful for bpftool gen skeleton)
socket_filter_kern.o: socket_filter_kern.c
        $(CLANG) -O2 -target bpf -D__TARGET_ARCH_x86 \
                -I/usr/include/x86_64-linux-gnu \
                -g -c $< -o $@

# Informational target — BPF objects are not linked into native executables
socket_filter_kern: socket_filter_kern.o
        @echo "Built BPF object file (no host linking needed)"

# Generate libbpf skeleton — provides type-safe access to programs/maps
# This header contains structs and helper functions like __open(), __load(), __attach()
socket_filter_kern.skel.h: socket_filter_kern.o
        bpftool gen skeleton $< > $@

# Link user-space program
# Required libraries:
# -lbpf  → libbpf itself
# -lelf  → ELF file handling
# -lz    → compression support
socket_filter_user: socket_filter_user.c socket_filter_kern.skel.h
        clang -O2 -g -Wall -I/usr/include \
                -lbpf -lelf -lz \
                socket_filter_user.c -o $@

# Convenience target to ensure skeleton exists
skeleton: socket_filter_kern.skel.h

# Clean build artifacts
clean:
        rm -f $(OBJS) $(USER_TARGETS) socket_filter_kern.skel.h
