

#ifndef EVENTS

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <linux/limits.h>

// 네트워크
#define MAX_PKT_SIZE 9216
struct Network_event {

    int ifindex;
    unsigned int pkt_len;
    bool is_INGRESS;
    int protocol;
    char ipSrc[16];
    unsigned int portSrc;

    char ipDst[16];
    unsigned int portDst;

    unsigned char RawPacket[MAX_PKT_SIZE];
};

#endif