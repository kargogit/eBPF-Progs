# Makefile
CLANG ?= clang
OBJS = cgroup_skb_counter_kern.o
USER_TARGETS = cgroup_counter_user

.PHONY: all clean skeleton

all: $(USER_TARGETS) skeleton

cgroup_skb_counter_kern.o: cgroup_skb_counter_kern.c
        $(CLANG) -O2 -target bpf -D__TARGET_ARCH_x86 -g -c $< -o $@

cgroup_skb_counter_kern.skel.h: cgroup_skb_counter_kern.o
        bpftool gen skeleton $< > $@

cgroup_counter_user: cgroup_skb_counter_user.c cgroup_skb_counter_kern.skel.h
        $(CLANG) -O2 -g -Wall -lbpf -lelf -lz $< -o $@

skeleton: cgroup_skb_counter_kern.skel.h

clean:
        rm -f $(OBJS) $(USER_TARGETS) cgroup_skb_counter_kern.skel.h
