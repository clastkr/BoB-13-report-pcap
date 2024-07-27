#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>

void packet_handler(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data) {
    struct ether_header *eth_header;
    struct ip *ip_header;
    struct tcphdr *tcp_header;
    int ip_header_length;
    int tcp_header_length;
    int total_headers_size, data_length;
    u_char *data;

    eth_header = (struct ether_header *)pkt_data;
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        ip_header = (struct ip *)(pkt_data + sizeof(struct ether_header));
        ip_header_length = ip_header->ip_hl * 4;

        if (ip_header->ip_p == IPPROTO_TCP) {
            tcp_header = (struct tcphdr *)((u_char *)ip_header + ip_header_length);
            tcp_header_length = tcp_header->th_off * 4;

            if (pkt_header->len < sizeof(struct ether_header) + ip_header_length + tcp_header_length) {
                fprintf(stderr, "Invalid packet size\n");
                return;
            }

            total_headers_size = sizeof(struct ether_header) + ip_header_length + tcp_header_length;
            data_length = pkt_header->len - total_headers_size;
            data = (u_char *)pkt_data + total_headers_size;

            printf("SRC MAC: %s, ", ether_ntoa((struct ether_addr *)eth_header->ether_shost));
            printf("DST MAC: %s\n", ether_ntoa((struct ether_addr *)eth_header->ether_dhost));
            printf("SRC IP: %s, ", inet_ntoa(ip_header->ip_src));
            printf("DST IP: %s\n", inet_ntoa(ip_header->ip_dst));
            printf("SRC PORT: %d, ", ntohs(tcp_header->th_sport));
            printf("DST PORT: %d\n", ntohs(tcp_header->th_dport));
            printf("DATA (up to 20 bytes): ");
            for (int i = 0; i < data_length && i < 20; i++) {
                printf("%02x ", data[i]);
            }
            printf("\n\n");
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Syntax: %s <interface>\n", argv[0]);
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", argv[1], errbuf);
        return 2;
    }

    pcap_loop(handle, 0, packet_handler, NULL);
    pcap_close(handle);
    return 0;
}
