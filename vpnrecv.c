#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<linux/if_tun.h>
#include<linux/if.h>
#include<sys/ioctl.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<fcntl.h>
#include<unistd.h>
#include<arpa/inet.h>
#include<poll.h>
#include<netpacket/packet.h>

#include "netutil.h"

#define VIRNIC_NAME "sampletun0"
#define VIRNIC_IP_ADDR "192.168.50.1"
#define VIRNIC_NETMASK "255.255.255.0"

#define ETHNIC_NAME "enp2s0f0"
#define ETHNIC_IP_ADDR "192.168.80.1"
#define ETHNIC_NETMASK "255.255.255.0"

#define READ_BUF_SIZE 2048

int virnic_fd;

static int virnicOpen() {
    virnic_fd = open("/dev/net/tun", O_RDWR);
    if(virnic_fd < 0) {
        perror("virnicOpen = virnic_fd create error");
        return -1;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, VIRNIC_NAME, IFNAMSIZ -1);
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if(ioctl(virnic_fd, TUNSETIFF, &ifr) != 0) {
        perror("virnicOpen = virnic_fd setting error");
        return -1;
    }
    return 0;
}

static int virnicSetting() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0) {
        perror("virnicSetting = socket create error");
        return -1;
    }

    struct ifreq ifr;
    struct sockaddr_in *p;

    //setting ip addr
    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, VIRNIC_NAME, IFNAMSIZ -1);
    p = (struct sockaddr_in*)&ifr.ifr_addr;
    p->sin_family = AF_INET;
    p->sin_addr.s_addr = inet_addr(VIRNIC_IP_ADDR);
    if(ioctl(sock, SIOCSIFADDR, &ifr) != 0) {
        perror("virnicSetting = ip addr setting error");
        return -1;
    }

    //setting netmask
    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, VIRNIC_NAME, IFNAMSIZ -1);
    p = (struct sockaddr_in*)&ifr.ifr_netmask;
    p->sin_family = AF_INET;
    p->sin_addr.s_addr = inet_addr(VIRNIC_NETMASK);
    if(ioctl(sock, SIOCSIFNETMASK, &ifr) != 0) {
        perror("virnicSetting = netmask setting error");
        return -1;
    }

    //setting ip link on
    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, VIRNIC_NAME, IFNAMSIZ -1);
    if(ioctl(sock, SIOCGIFFLAGS, &ifr) != 0) {
        perror("virnicSetting = flags getting error");
        return -1;
    }
    ifr.ifr_flags |= IFF_RUNNING | IFF_UP;
    if(ioctl(sock, SIOCSIFFLAGS, &ifr) != 0) {
        perror("virnicSetting = flags setting error");
        return -1;
    }

    return 0;
}

static int ethNicSetting() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0) {
        perror("virnicSetting = socket create error");
        return -1;
    }

    struct ifreq ifr;
    struct sockaddr_in *p;

    //setting ip addr
    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, ETHNIC_NAME, IFNAMSIZ -1);
    p = (struct sockaddr_in*)&ifr.ifr_addr;
    p->sin_family = AF_INET;
    p->sin_addr.s_addr = inet_addr(ETHNIC_IP_ADDR);
    if(ioctl(sock, SIOCSIFADDR, &ifr) != 0) {
        perror("virnicSetting = ip addr setting error");
        return -1;
    }

    //setting netmask
    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, ETHNIC_NAME, IFNAMSIZ -1);
    p = (struct sockaddr_in*)&ifr.ifr_netmask;
    p->sin_family = AF_INET;
    p->sin_addr.s_addr = inet_addr(ETHNIC_NETMASK);
    if(ioctl(sock, SIOCSIFNETMASK, &ifr) != 0) {
        perror("virnicSetting = netmask setting error");
        return -1;
    }

    //setting ip link on
    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, ETHNIC_NAME, IFNAMSIZ -1);
    if(ioctl(sock, SIOCGIFFLAGS, &ifr) != 0) {
        perror("virnicSetting = flags getting error");
        return -1;
    }
    ifr.ifr_flags |= IFF_RUNNING | IFF_UP;
    if(ioctl(sock, SIOCSIFFLAGS, &ifr) != 0) {
        perror("virnicSetting = flags setting error");
        return -1;
    }

    return 0;
}

int main(int argc, char* argv) {
    if(virnicOpen() != 0) {
        exit(1);
    }

    if(virnicSetting() != 0) {
        exit(1);
    }

    if(ethNicSetting() != 0) {
        exit(1);
    }

    int ethsock = socket(PF_PACKET, SOCK_RAW, swapon16(ETH_P_ALL));
    if(ethsock < 0) {
        perror("eth raw sock\n");
        exit(1);
    }
    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, ETHNIC_NAME, IFNAMSIZ - 1);
    if(ioctl(ethsock, SIOCGIFINDEX, &ifr) != 0) {
        perror("ioctl ");
        exit(1);
    }
    addr.sll_ifindex = ifr.ifr_ifindex;
    addr.sll_family = PF_PACKET;
    addr.sll_protocol = swapon16(ETH_P_ALL);
    if(bind(ethsock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("bind error ");
        exit(1);
    }

    struct pollfd pfd[2];
    memset(pfd, 0, sizeof(pfd));
    pfd[0].fd = virnic_fd;
    pfd[0].events = POLLIN | POLLERR;
    pfd[1].fd = ethsock;
    pfd[1].events = POLLIN | POLLERR;

    int readSize = 0;
    char buf[READ_BUF_SIZE];

    IPHDR *iphp;
    while(1) {
        memset(buf, 0, sizeof(buf));
        poll(pfd, 2, -1);
        if(pfd[1].revents & POLLIN) {
            readSize = read(pfd[1].fd, buf, sizeof(buf));
            printf("eth nic get\n");
            ETHHDR* ep = (ETHHDR*)buf;
            printf("protocol 0x%x\n", swapon16(ep->protocol));
            
            IPHDR* eip = (IPHDR*)(buf + sizeof(ETHHDR));
            printIpAddr(eip);
            write(pfd[0].fd, (char*)(buf + sizeof(ETHHDR)), readSize - sizeof(ETHHDR));
            // iphp = (IPHDR*)buf;
            // printIpAddr(iphp);
        }
        if(pfd[0].revents & POLLIN) {
            readSize = read(pfd[0].fd, buf, sizeof(buf));
            iphp = (IPHDR*)buf;
            printIpAddr(iphp);
        }
    }
    
    close(virnic_fd);
    return 0;
}