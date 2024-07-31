#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>
#include <arpa/inet.h>

void usage() {
    printf("./pcap-test <interface>\n");
}

typedef struct {
    char* dev;
} Param;

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev = argv[1];
    return true;
}

typedef struct {
    struct libnet_ethernet_hdr* eth_header;
    struct libnet_ipv4_hdr* ip_header;
    struct libnet_tcp_hdr* tcp_header;
    const u_char* payload;
    int payload_len;
} PacketInfo;

void parse_packet(const u_char* packet, int packet_len, PacketInfo* info) {
    info->eth_header = (struct libnet_ethernet_hdr*) packet;
    info->ip_header = (struct libnet_ipv4_hdr*) (packet + sizeof(struct libnet_ethernet_hdr));
    info->tcp_header = (struct libnet_tcp_hdr*) ((u_char*) info->ip_header + (info->ip_header->ip_hl << 2));
    info->payload = (u_char*) info->tcp_header + (info->tcp_header->th_off << 2);
    info->payload_len = packet_len - (info->payload - packet);
}

void print_packet_info(const PacketInfo* info) {
    printf("SRC MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
           info->eth_header->ether_shost[0], info->eth_header->ether_shost[1], info->eth_header->ether_shost[2],
           info->eth_header->ether_shost[3], info->eth_header->ether_shost[4], info->eth_header->ether_shost[5]);
    printf("DST MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
           info->eth_header->ether_dhost[0], info->eth_header->ether_dhost[1], info->eth_header->ether_dhost[2],
           info->eth_header->ether_dhost[3], info->eth_header->ether_dhost[4], info->eth_header->ether_dhost[5]);

    printf("SRC IP: %s\n", inet_ntoa(info->ip_header->ip_src));
    printf("DST IP: %s\n", inet_ntoa(info->ip_header->ip_dst));

    printf("SRC PORT: %d\n", ntohs(info->tcp_header->th_sport));
    printf("DST PORT: %d\n", ntohs(info->tcp_header->th_dport));

    printf("DATA: ");
    for (int i = 0; i < info->payload_len && i < 20; i++) {
        printf("%02x ", info->payload[i]);
    }
    printf("\n");
}

int main(int argc, char* argv[]) {
    Param param;
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev, BUFSIZ, 1, 1000, errbuf);

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res <= 0) continue;

        PacketInfo info;
        parse_packet(packet, header->caplen, &info);

        print_packet_info(&info);
        printf("\n");
    }

    pcap_close(pcap);
}
