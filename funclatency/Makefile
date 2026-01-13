# Makefile
CLANG ?= clang
OBJS = funclatency_kern.o
USER_TARGETS = funclatency_user

.PHONY: all clean skeleton

all: $(USER_TARGETS) skeleton

funclatency_kern.o: funclatency_kern.c
        $(CLANG) -O2 -target bpf -D__TARGET_ARCH_x86 -g -c $< -o $@

funclatency_kern.skel.h: funclatency_kern.o
        bpftool gen skeleton $< > $@

funclatency_user: funclatency_user.c funclatency_kern.skel.h
        $(CLANG) -O2 -g -Wall -lbpf -lelf -lz $< -o $@

skeleton: funclatency_kern.skel.h

clean:
        rm -f $(OBJS) $(USER_TARGETS) funclatency_kern.skel.h
