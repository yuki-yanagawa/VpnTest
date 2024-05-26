#include<stdio.h>

#include "netutil.h"

uint16_t swapon16(uint16_t data) {
    return (data >> 8 & 0x00ff) | (data << 8 & 0xff00);
}

uint32_t swapon32(uint32_t data) {
    return (data >> 24  & 0x000000ff) | (data >> 8 & 0x0000ff00) | (data << 24 & 0xff000000) | (data << 8 & 0x00ff0000);
}

void printIpAddr(IPHDR* iph) {
    uint32_t srcip = swapon32(iph->srcip);
    uint32_t destip = swapon32(iph->destip);
    printf("++++ ip addr +++++++++++++\n");
    printf("src ip addr : %d.%d.%d.%d\n", (srcip>>24 & 0xff), (srcip>>16 & 0xff), (srcip>>8 & 0xff), (srcip & 0xff));
    printf("dest ip addr : %d.%d.%d.%d\n", (destip>>24 & 0xff), (destip>>16 & 0xff), (destip>>8 & 0xff), (destip & 0xff));
    printf("++++ ip addr +++++++++++++\n");
    printf("\n");
}