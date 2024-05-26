#ifndef NETUTIL_H_
#define NETUTIL_H_

#include "common.h"
#include<linux/if_ether.h>

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif

typedef struct {
    uint8_t vhl;
    uint8_t tos;
    uint16_t tol;

    uint16_t id;
    uint16_t frags;

    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    
    uint32_t srcip;
    uint32_t destip;
    uint8_t opt[];
} IPHDR;

typedef struct {
    uint8_t shdaddr[6];
    uint8_t dhdaddr[6];
    uint16_t protocol;
} __attribute__((packed)) ETHHDR;

uint16_t swapon16(uint16_t data);
uint32_t swapon32(uint32_t data);
void printIpAddr(IPHDR* iph);



#endif