// exitsnoop.h
#ifndef __EXITSNOOP_H
#define __EXITSNOOP_H

#define TASK_COMM_LEN 16

struct event {
    unsigned int pid;
    int exit_code;
    char comm[TASK_COMM_LEN];
};

#endif
