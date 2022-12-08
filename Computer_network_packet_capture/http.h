#pragma once

int http_main();
void http_packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
void http_ip_layer(const pcap_pkthdr*, const u_char*);
void print_http(const pcap_pkthdr* header, u_char* data, int dataLen);