#include "arp.h"

#include <arpa/inet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <csignal>
#include <string>
#include <vector>

// Define some constants.
#define IP4_HDRLEN 20    // IPv4 header length
#define ETH2_HEADER_LEN 14

struct NFQData{
  AccessInfo info;
  std::map<std::vector<uint8_t>, std::vector<uint8_t>> ip_mac_pairs;
};

struct dns_hdr {
  uint16_t id;
  uint16_t flags;
  uint16_t qs_cnt;
  uint16_t ans_cnt;
  uint16_t authrr_cnt;
  uint16_t addrr_cnt;
};


struct __attribute__((packed, aligned(2))) resp_hdr {
  uint16_t name;
  uint16_t type;
  uint16_t cls; // class
  uint32_t ttl;
  uint16_t len;
};

struct __attribute__((packed, aligned(1))) ip_hdr {
  uint8_t ihl:4, ver:4;
  uint8_t tos;
  uint16_t tlen;
  uint16_t id;
  uint16_t flags;
  uint8_t ttl;
  uint8_t proto;
  uint16_t checksum;
  uint32_t src_ip;
  uint32_t dst_ip;
};
struct udp_hdr {
  uint16_t src_port;
  uint16_t dst_port;
  uint16_t len;
  uint16_t checksum;
};

void receiveHandler(int sockfd, std::map<std::vector<uint8_t>, std::vector<uint8_t>> &ip_mac_pairs, AccessInfo info);