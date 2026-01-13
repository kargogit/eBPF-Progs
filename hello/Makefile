# Makefile for eBPF Hello World

CLANG ?= clang
PACKAGE_NAME = hello_world
OBJS = hello_kern.o

# User-space component
USER_TARGETS = hello_user

.PHONY: all clean hello_kern

all: $(USER_TARGETS) skeleton

# Compile the kernel eBPF program
hello_kern.o: hello_kern.c
	$(CLANG) -O2 -target bpf -D__TARGET_ARCH_x86 \
		-I/usr/include \
		-g -O2 -c $< -o $@

# Prevent make from trying to create a host binary named "hello_kern"
# (this is a no-op informational target)
hello_kern: hello_kern.o
	@echo "Built $< (BPF object). Not linking into a host executable."

# Generate the skeleton header
hello_kern.skel.h: hello_kern.o
	bpftool gen skeleton $< > $@

# Compile the user-space program
hello_user: hello_user.c hello_kern.skel.h
	clang -O2 -g -Wall -I/usr/include \
		-lbpf -lelf -lz \
		hello_user.c -o $@

# Dependency targets
skeleton: hello_kern.skel.h

clean:
	rm -f $(OBJS) $(USER_TARGETS) hello_kern.skel.h
