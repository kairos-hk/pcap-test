#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <pcap.h>

void eth_header(const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *)packet;

    printf("SRC MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
           eth_header -> ether_shost[0], eth_header -> ether_shost[1], eth_header -> ether_shost[2],
           eth_header -> ether_shost[3], eth_header -> ether_shost[4], eth_header -> ether_shost[5]);
    
	printf("DST MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
           eth_header -> ether_dhost[0], eth_header -> ether_dhost[1], eth_header -> ether_dhost[2],
           eth_header -> ether_dhost[3], eth_header -> ether_dhost[4], eth_header -> ether_dhost[5]);
}

void ip_header(const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));

    printf("SRC IP: %s\n", inet_ntoa(ip_header -> ip_src));
    printf("DST IP: %s\n", inet_ntoa(ip_header -> ip_dst));
}


void tcp_header(const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));

    struct tcphdr *tcp_header = (struct tcphdr *)((u_char *)ip_header + (ip_header->ip_hl << 2));

    printf("SRC PORT: %d\n", ntohs(tcp_header -> th_sport));
    printf("DST PORT: %d\n", ntohs(tcp_header -> th_dport));
}


void payload(const u_char *packet, int packet_len) {
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    struct tcphdr *tcp_header = (struct tcphdr *)((u_char *)ip_header + (ip_header->ip_hl << 2));

    u_char *data = (u_char *)tcp_header + (tcp_header->th_off << 2);
    int data_len = packet_len - (data - packet);

    printf("DATA: ");
    for (int i = 1; i < data_len && i < 21; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);

    struct pcap_pkthdr header;
    const u_char *packet;

    while ((packet = pcap_next(handle, &header))) {
        eth_header(packet);
        ip_header(packet);
        tcp_header(packet);
        payload(packet, header.len);
        printf("\n");
		printf("-----------------------------------------------------------");
		printf("\n");
    }

    pcap_close(handle);
}