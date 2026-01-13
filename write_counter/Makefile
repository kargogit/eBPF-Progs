# Makefile
CLANG ?= clang
OBJS = write_counter_kern.o
USER_TARGETS = write_counter_user

.PHONY: all clean skeleton

all: $(USER_TARGETS) skeleton

write_counter_kern.o: write_counter_kern.c
        $(CLANG) -O2 -target bpf -D__TARGET_ARCH_x86 -g -c $< -o $@

write_counter_kern.skel.h: write_counter_kern.o
        bpftool gen skeleton $< > $@

write_counter_user: write_counter_user.c write_counter_kern.skel.h
        clang -O2 -g -Wall -lbpf -lelf -lz $< -o $@

skeleton: write_counter_kern.skel.h

clean:
        rm -f $(OBJS) $(USER_TARGETS) write_counter_kern.skel.h
