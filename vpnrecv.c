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
#include<net/route.h>
#include<sys/wait.h>

#include "netutil.h"

#define VIRNIC_NAME "sampletun0"
#define VIRNIC_IP_ADDR "192.168.50.1"
#define VIRNIC_NETMASK "255.255.255.0"

#define ETHNIC_NAME "enp2s0f0"
#define ETHNIC_IP_ADDR "192.168.80.1"
#define ETHNIC_NETMASK "255.255.255.0"

#define RTDST "192.168.80.0"
#define RTGATEWAY "192.168.50.1"
#define RTGENMASK "255.255.255.0"

#define READ_BUF_SIZE 2048

#define DEBUG_ON

int virnic_fd;
int neworkAddr[3];

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

static void routeSetting() {
    struct rtentry route;
    struct sockaddr_in *addr;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    memset(&route, 0, sizeof(route));

    addr = (struct sockaddr_in*)&route.rt_dst;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr(RTDST);

    addr = (struct sockaddr_in*)&route.rt_gateway;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr(RTGATEWAY);

    addr = (struct sockaddr_in*)&route.rt_genmask;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr(RTGENMASK);

    route.rt_flags = RTF_UP | RTF_GATEWAY;
    route.rt_dev = "sampletun0";
    route.rt_metric = 100;

    /* Add the route */
    if(ioctl(fd, SIOCADDRT, route) != 0) {
        perror("error");
        exit(-1);
    }
    sleep(30);
    ioctl(fd, SIOCDELRT, route);
}

static void getVirNicNetWorkAddr(int* retNetWorkAddr) {
    char del = '.';
    char buf[3];
    int index;
    char* p = VIRNIC_IP_ADDR;
    int* retP = retNetWorkAddr;

    memset(buf,0,sizeof(buf));
    index = 0;
    while(*p != del) {
        buf[index++] = *p++;
    }
    buf[index] = '\0';
    *retP++ = atoi(buf);
    //skip '.'
    p++;

    memset(buf,0,sizeof(buf));
    index = 0;
    while(*p != del) {
        buf[index++] = *p++;
    }
    buf[index] = '\0';
    *retP++ = atoi(buf);
    //skip '.'
    p++;

    memset(buf,0,sizeof(buf));
    index = 0;
    while(*p != del) {
        buf[index++] = *p++;
    }
    buf[index] = '\0';
    *retP++ = atoi(buf);
    //skip '.'
    p++;
}

static bool checkNetWork(uint32_t ipaddr) {
    return (ipaddr >> 24 & 0xff) == neworkAddr[0] && (ipaddr >> 16 & 0xff) == neworkAddr[1] && (ipaddr >> 8 & 0xff) == neworkAddr[2];
}

static void ipforwardSettingON() {
    pid_t pid = fork();
    if(pid == 0) {
        char* execargv[] ={"/sbin/sysctl", "-w", "net.ipv4.ip_forward=1", NULL};
        execve("/sbin/sysctl", execargv, NULL);
    }
    int status = 0;
    wait(&status);
    if(status != 0) {
        perror("ipforward setting error....");
        exit(1);
    }
}

static void ipforwardSettingOFF() {
    pid_t pid = fork();
    if(pid == 0) {
        char* execargv[] ={"/sbin/sysctl", "-w", "net.ipv4.ip_forward=0", NULL};
        execve("/sbin/sysctl", execargv, NULL);
    }
    int status = 0;
    wait(&status);
    if(status != 0) {
        perror("ipforward setting error....");
        exit(1);
    }
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

    // routeSetting();

    ipforwardSettingON();

    //virnicNetWorkAddrSetting
    memset(neworkAddr, 0, sizeof(neworkAddr));
    getVirNicNetWorkAddr(neworkAddr);
#ifdef DEBUG_ON
    printf("Net work addr %d.%d.%d\n", neworkAddr[0], neworkAddr[1], neworkAddr[2]);
#endif

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
        if(pfd[0].revents & POLLIN) {
            readSize = read(pfd[0].fd, buf, sizeof(buf));
            iphp = (IPHDR*)buf;
            if(checkNetWork(swapon32(iphp->destip))) {
                printf("****** vir nic *******\n");
                printIpAddr(iphp);
                printf("****** vir nic *******\n");
                printf("\n");
            }
        }
        if(pfd[1].revents & POLLIN) {
            readSize = read(pfd[1].fd, buf, sizeof(buf));
            // printf("eth nic get\n");
            ETHHDR* ep = (ETHHDR*)buf;
            // printf("protocol 0x%x\n", swapon16(ep->protocol));
            if(swapon16(ep->protocol) == ETHER_IP_PROTOCOL) {
                IPHDR* eip = (IPHDR*)(buf + sizeof(ETHHDR));
                if(checkNetWork(swapon32(eip->destip))) {
                    printf("****** eth nic *******\n");
                    printIpAddr(eip);
                    printf("****** eth nic *******\n");
                    printf("\n");
                    write(pfd[0].fd, (char*)(buf + sizeof(ETHHDR)), readSize - sizeof(ETHHDR));
                }
            }
        }
    }
    
    ipforwardSettingOFF();
    close(virnic_fd);
    return 0;
}