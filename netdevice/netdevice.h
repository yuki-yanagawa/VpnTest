#include "common.h"

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

struct net_device {
    uint32_t index;
    char name[IFNAMSIZ];
    uint8_t macaddr[6];
    uint32_t ipaddr;
    uint32_t netmask;
};

struct net_device_ops {
    int (*open)(struct net_device *dev);
    int (*close)(struct net_device *dev);
    int (*transmit)(struct net_device *dev);
};