#pragma once



typedef struct ip_address;
typedef struct ip_header;
typedef struct udp_header;

void udp_packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
int UDP_main();