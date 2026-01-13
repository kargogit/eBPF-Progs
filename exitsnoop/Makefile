# Makefile
CLANG ?= clang
OBJS = exitsnoop_kern.o
USER_TARGETS = exitsnoop_user

.PHONY: all clean skeleton

all: vmlinux.h $(USER_TARGETS) skeleton

vmlinux.h:
        bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

exitsnoop_kern.o: exitsnoop_kern.c vmlinux.h
        $(CLANG) -O2 -target bpf -D__TARGET_ARCH_x86 -g -c $< -o $@

exitsnoop_kern.skel.h: exitsnoop_kern.o
        bpftool gen skeleton $< > $@

exitsnoop_user: exitsnoop_user.c exitsnoop_kern.skel.h
        clang -O2 -g -Wall -lbpf -lelf -lz $< -o $@

skeleton: exitsnoop_kern.skel.h

clean:
        rm -f $(OBJS) $(USER_TARGETS) exitsnoop_kern.skel.h vmlinux.h
