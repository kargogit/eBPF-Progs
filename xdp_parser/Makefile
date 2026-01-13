# Makefile
CLANG ?= clang
OBJS = xdp_parser_kern.o
USER_TARGETS = xdp_parser_user

.PHONY: all clean skeleton

all: $(USER_TARGETS) skeleton

# Compile eBPF kernel program
xdp_parser_kern.o: xdp_parser_kern.c
        $(CLANG) -O2 -target bpf -D__TARGET_ARCH_x86 -g -c $< -o $@

# Generate skeleton header
xdp_parser_kern.skel.h: xdp_parser_kern.o
        bpftool gen skeleton $< > $@

# Build user-space program
xdp_parser_user: xdp_parser_user.c xdp_parser_kern.skel.h
        $(CLANG) -O2 -g -Wall -lbpf -lelf -lz $< -o $@

skeleton: xdp_parser_kern.skel.h

clean:
        rm -f $(OBJS) $(USER_TARGETS) xdp_parser_kern.skel.h
