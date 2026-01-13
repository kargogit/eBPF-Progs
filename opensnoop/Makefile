# Makefile
CLANG ?= clang
OBJS = opensnoop_kern.o
USER_TARGETS = opensnoop_user

.PHONY: all clean skeleton

all: $(USER_TARGETS) skeleton

opensnoop_kern.o: opensnoop_kern.c
        $(CLANG) -O2 -target bpf -D__TARGET_ARCH_x86 -g -c $< -o $@

opensnoop_kern.skel.h: opensnoop_kern.o
        bpftool gen skeleton $< > $@

opensnoop_user: opensnoop_user.c opensnoop_kern.skel.h
        clang -O2 -g -Wall -lbpf -lelf -lz $< -o $@

skeleton: opensnoop_kern.skel.h

clean:
        rm -f $(OBJS) $(USER_TARGETS) opensnoop_kern.skel.h
