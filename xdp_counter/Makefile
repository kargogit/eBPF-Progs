# Makefile
CLANG ?= clang
OBJS = xdp_counter_kern.o
USER_TARGETS = xdp_counter_user

.PHONY: all clean skeleton

all: $(USER_TARGETS) skeleton

xdp_counter_kern.o: xdp_counter_kern.c
        $(CLANG) -O2 -target bpf -D__TARGET_ARCH_x86 -g -c $< -o $@

xdp_counter_kern.skel.h: xdp_counter_kern.o
        bpftool gen skeleton $< > $@

xdp_counter_user: xdp_counter_user.c xdp_counter_kern.skel.h
        $(CLANG) -O2 -g -Wall -lbpf -lelf -lz $< -o $@

skeleton: xdp_counter_kern.skel.h

clean:
        rm -f $(OBJS) $(USER_TARGETS) xdp_counter_kern.skel.h
