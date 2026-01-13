# Makefile
CLANG ?= clang
OBJS = xdp_dropper_kern.o
USER_TARGETS = xdp_dropper_user

.PHONY: all clean skeleton

all: $(USER_TARGETS) skeleton

# Compile the eBPF kernel program
xdp_dropper_kern.o: xdp_dropper_kern.c
        $(CLANG) -O2 -target bpf -D__TARGET_ARCH_x86 -g -c $< -o $@

# Generate skeleton header
xdp_dropper_kern.skel.h: xdp_dropper_kern.o
        bpftool gen skeleton $< > $@

# Build user-space program
xdp_dropper_user: xdp_dropper_user.c xdp_dropper_kern.skel.h
        $(CLANG) -O2 -g -Wall -lbpf -lelf -lz $< -o $@

skeleton: xdp_dropper_kern.skel.h

clean:
        rm -f $(OBJS) $(USER_TARGETS) xdp_dropper_kern.skel.h
