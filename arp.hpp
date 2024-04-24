#include "local.hpp"

#include <linux/if_arp.h>
#include <netinet/ip_icmp.h>

#include <algorithm>
#include <map>
#include <thread>

#define ETH_HDRLEN 14  // Ethernet header length
#define ARP_HDRLEN 28  // ARP header length

// Define a struct for ARP header
struct arp_hdr {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t opcode;
    std::vector<uint8_t> sender_mac;
    std::vector<uint8_t> sender_ip;
    std::vector<uint8_t> target_mac;
    std::vector<uint8_t> target_ip;
};

void sendARPRequest(int sd, struct LocalInfo local_info);
void sendSpoofedARPReply(int sd, std::map<std::vector<uint8_t>, std::vector<uint8_t>> &ip_mac_pairs, struct LocalInfo local_info);
void parseARPReply(uint8_t *buffer, std::map<std::vector<uint8_t>, std::vector<uint8_t>> &ip_mac_pairs, struct LocalInfo local_info);
