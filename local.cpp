#include "local.h"     

void AccessInfo::getInfo(){
    int sockfd;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    
    // get gatewy and interface
    getDefault();
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);
    device.sll_ifindex = if_nametoindex(interface); // set index
    
    // send request to look up interface
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("socket() failed");
        exit(EXIT_FAILURE);
    }
    
    // get src_ip
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFADDR failed");
        return;
    }
    memcpy(&src_ip, &ifr.ifr_addr, sizeof(struct sockaddr_in));
    
    // get src_mac
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFHWADDR failed");
        return;
    }
    std::copy(ifr.ifr_hwaddr.sa_data, ifr.ifr_hwaddr.sa_data + 6, src_mac.begin()); // copy first six byte of ifr_hwaddr.sa_data to src_mac
    
    // get netmask
    if (ioctl(sockfd, SIOCGIFNETMASK, &ifr) < 0) {
        perror("ioctl SIOCGIFNETMASK failed");
        return;
    }
    memcpy(&netmask, &ifr.ifr_netmask, sizeof(struct sockaddr_in));
    close(sockfd);
}


void AccessInfo::getDefault() {
    FILE *fp = fopen("/proc/net/route", "r");

    char line[100], iface[20];
    unsigned long dest, gateway;
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%s\t%lX\t%lX", iface, &dest, &gateway) == 3) {
            if (dest == 0) {  // Default interface
                strcpy(interface, iface);
                gateway_ip.sin_family = AF_INET;
                gateway_ip.sin_addr.s_addr = gateway;
                break;
            }
        }
    }

    fclose(fp);
}

// int main(int argc, char **argv){
//     int sockfd;
//     AccessInfo access_info;

//     access_info.getInfo();

//     printf("src_ip: %s\n", inet_ntoa(access_info.src_ip.sin_addr));
//     printf("src_mac: %02x:%02x:%02x:%02x:%02x:%02x\n", access_info.src_mac[0], access_info.src_mac[1], access_info.src_mac[2], access_info.src_mac[3], access_info.src_mac[4], access_info.src_mac[5]);
//     printf("netmask: %s\n", inet_ntoa(access_info.netmask.sin_addr));
//     printf("Index for interface %s is %i\n", access_info.interface, access_info.device.sll_ifindex);
//     printf("gateway_ip: %s\n", inet_ntoa(access_info.gateway_ip.sin_addr));
//     return 0;
// }