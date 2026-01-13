/* cgroup_skb_counter.h */
#ifndef __COMMON_H
#define __COMMON_H

#include <linux/types.h>

struct datarec {
    __u64 packets;
    __u64 bytes;
};

#define INGRESS_KEY 0
#define EGRESS_KEY  1

#endif
