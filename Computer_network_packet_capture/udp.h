#pragma once
/* prototype of the packet handler */
int udp_main();
void udp_packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
void udp_ip_layer(const pcap_pkthdr*, const u_char*);
void print_udp(u_char* data);