# Makefile
CLANG ?= clang
OBJS = execsnoop_kern.o
USER_TARGETS = execsnoop_user

.PHONY: all clean skeleton

all: vmlinux.h $(USER_TARGETS) skeleton

vmlinux.h:
        bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

execsnoop_kern.o: execsnoop_kern.c vmlinux.h
        $(CLANG) -O2 -target bpf -D__TARGET_ARCH_x86 -g -c $< -o $@

execsnoop_kern.skel.h: execsnoop_kern.o
        bpftool gen skeleton $< > $@

execsnoop_user: execsnoop_user.c execsnoop_kern.skel.h
        clang -O2 -g -Wall -lbpf -lelf -lz $< -o $@

skeleton: execsnoop_kern.skel.h

clean:
        rm -f $(OBJS) $(USER_TARGETS) execsnoop_kern.skel.h vmlinux.h
