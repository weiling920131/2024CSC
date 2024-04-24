#include <linux/if_packet.h>
#include <sys/types.h>   
#include <sys/ioctl.h>   
#include <sys/socket.h>  
#include <net/if.h> 
#include <netinet/in.h> 
#include <unistd.h>  
#include <cstdlib>  
#include <vector>
#include <cstdio>   
#include <cstring>
#include <arpa/inet.h>

class AccessInfo{
public:
    std::vector<uint8_t> src_mac;
    struct sockaddr_in src_ip;
    struct sockaddr_in netmask;
    struct sockaddr_in gateway_ip;
    struct sockaddr_ll device;

    AccessInfo(){
        src_mac.resize(6);
    };

    ~AccessInfo() = default;

    void getInfo(char *interface);
    void getDefaultGateway(char *interface);
};