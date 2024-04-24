#include <linux/if_packet.h>
#include <sys/types.h>   
#include <sys/ioctl.h>   
#include <sys/socket.h>  
#include <net/if.h> 
#include <netinet/in.h> 
#include <arpa/inet.h>
#include <unistd.h>  
#include <cstdlib>  
#include <cstdio>   
#include <cstring>
#include <vector>

class AccessInfo{
public:
    std::vector<uint8_t> src_mac;
    struct sockaddr_in src_ip;
    struct sockaddr_in netmask;
    struct sockaddr_in gateway_ip;
    struct sockaddr_ll device;
    char interface[20];

    AccessInfo(){
        src_mac.resize(6);
    };

    ~AccessInfo() = default;

    void getInfo();
    void getDefault();
};