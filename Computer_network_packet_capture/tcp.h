#pragma once

int tcp_main();
void tcp_packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
void tcpheader(const u_char* pkt_data);
void pr_tcpflag(int flag);