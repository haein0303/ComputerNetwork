#pragma once

/* prototype of the packet handler */
int dns_main();
void dns_packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
void ip_layer(const pcap_pkthdr*, const u_char*);
void print_dns(const pcap_pkthdr* header, u_char*);
