#include <stdio.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>


void tcp_packet(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    struct ether_header *eth_header = (struct ether_header *)packet;
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));

    if (ip_header->ip_p == IPPROTO_TCP){
        // Ethernet Header
        printf("Src MAC: %s\n", ether_ntoa((struct ether_addr *)eth_header->ether_shost));
        printf("Dst MAC: %s\n", ether_ntoa((struct ether_addr *)eth_header->ether_dhost));
        // IP Header
        printf("Src IP: %s\n", inet_ntoa(ip_header->ip_src));
        printf("Dst IP: %s\n", inet_ntoa(ip_header->ip_dst));
        // TCP Header
        printf("Src Port: %d\n", ntohs(tcp_header->th_sport));
        printf("Dst Port: %d\n", ntohs(tcp_header->th_dport));
        // Message
        int data_offset = sizeof(struct ether_header) + sizeof(struct ip) + tcp_header->th_off * 4;
        int data_length = pkthdr->len - data_offset;
        if (data_length > 0) {
            printf("Message[30byte]: ");
            for (int i = 0; i < data_length && i < 30; i++) {
                printf("%02X ", packet[data_offset + i]);
            }
            printf("\n");
        }
    }

}

int main() {
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    pcap_if_t *alldevs, *dev_list;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("Can't find network device list: %s\n", errbuf);
        return 1;
    }

    dev = alldevs->name;

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Can't open network device: %s\n", errbuf);
        return 1;
    }

    pcap_loop(handle, 0, tcp_packet, NULL);
    pcap_close(handle);
    return 0;
}
