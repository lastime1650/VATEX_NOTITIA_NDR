#ifndef EBPF_H
#define EBPF_H

#include <iostream>
#include <string>
#include <stdexcept>
#include <memory>
#include <csignal>
#include <cerrno>
#include <cstring>   // strerror
#include <net/if.h>  // if_nametoindex
#include <ifaddrs.h>
#include <vector>
#include <thread> 
#include <tuple>
#include <unordered_map>
#include <cstdlib>
#include <chrono>    // C++11 chrono 라이브러리
#include <cstdint>   // uint64_t를 위해
#include <atomic>
#include <fmt/core.h>


namespace NDR
{
    namespace Util
    {
        namespace eBPF
        {
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

            namespace QueueStruct
            {
                struct EbpfPacketQueueStruct
                {
                    unsigned long long timestamp;
                    unsigned long RawPacketSize;

                    
                    unsigned char* PacketEvent;
                };
            }
        }
    }
    
}

#endif