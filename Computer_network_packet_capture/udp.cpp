


#include "stdafx.h"
#include "udp.h"







using namespace std;





int udp_main()
{
	pcap_if_t* alldevs;
	pcap_if_t* d;
	int inum;
	int i = 0;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];

#ifdef _WIN32
	/* Load Npcap and its functions. */
	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}
#endif

	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure Npcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* Open the device */
	/* Open the adapter */
	if ((adhandle = pcap_open_live(d->name,	// name of the device
		65536,			// portion of the packet to capture. 
		// 65536 grants that the whole packet will be captured on all the MACs.
		1,				// promiscuous mode (nonzero means promiscuous)
		1000,			// read timeout
		errbuf			// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	/* start the capture */
	pcap_loop(adhandle, 0, udp_packet_handler, NULL);

	pcap_close(adhandle);
	return 0;
}


/* Callback function invoked by libpcap for every incoming packet */
void udp_packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{


	/*
	 * unused parameters
	 */
	(VOID)(param);
	int i;
	/* convert the timestamp to readable format */

	/*
	printf("raw");
	for (i = 1; (i < header->caplen + 1); i++)
	{
		printf("%.2x ", pkt_data[i - 1]);
		if ((i % LINE_LEN) == 0) printf("\n");
	}
	printf("\n");
	*/

	udp_ip_layer(header, pkt_data);

}

void udp_ip_layer(const pcap_pkthdr* header, const u_char* pkt_data) {

	u_char srcMac[6];
	u_char destMac[6];
	u_char lenType[2];
	u_char fcs[4];
	u_char* data = (u_char*)malloc(sizeof(u_char) * 65535);
	int idx = 0;
	for (int i = 0; i < 6; i++)
	{
		srcMac[i] = pkt_data[idx++];
	}
	for (int i = 0; i < 6; i++)
	{
		destMac[i] = pkt_data[idx++];
	}
	for (int i = 0; i < 2; i++)
	{
		lenType[i] = pkt_data[idx++];
	}
	int j = 0;

	while (idx < header->caplen) {
		data[j++] = pkt_data[idx++];
	}





	u_char versionNHeaderLen;
	int version;
	int headerLen;
	u_char TOS;
	u_char totalLen[2];
	u_char identification[2];
	u_char flagNFragmentOffset[2];
	int flag;
	int fragmentOffset;
	u_char ttl;
	u_char protocol;
	u_char headerChecksum[2];
	u_char srcAddr[4];
	u_char destAddr[4];
	idx = 0;
	versionNHeaderLen = data[idx++];
	version = (((int)versionNHeaderLen) & 240) >> 4;
	headerLen = (((int)versionNHeaderLen) & 15);

	TOS = data[idx++];
	for (int i = 0; i < 2; i++)
	{
		totalLen[i] = data[idx++];
	}
	int totalLenInt = totalLen[0] * 256 + totalLen[1];
	for (int i = 0; i < 2; i++)
	{
		identification[i] = data[idx++];
	}
	for (int i = 0; i < 2; i++)
	{
		flagNFragmentOffset[i] = data[idx++];
	}
	flag = (((int)flagNFragmentOffset) & 57344) >> 13;
	int flags[3];
	flags[0] = 0;
	flags[1] = (flag & 2) ? 1 : 0;
	flags[2] = (flag & 1);
	fragmentOffset = (((int)flagNFragmentOffset) & 131071);
	ttl = data[idx++];
	// tcp : 6, udp : 17
	protocol = data[idx++];
	for (int i = 0; i < 2; i++)
	{
		headerChecksum[i] = data[idx++];
	}
	for (int i = 0; i < 4; i++)
	{
		srcAddr[i] = data[idx++];
	}
	for (int i = 0; i < 4; i++)
	{
		destAddr[i] = data[idx++];
	}
	if (totalLenInt == 0) return;
	int dataLen = totalLenInt - (headerLen) * 4;
	u_char* ip_data = (u_char*)malloc(sizeof(u_char) * (dataLen));
	for (int i = 0; i < dataLen; i++)
	{
		ip_data[i] = data[headerLen * 4 + i];
	}
	//이더넷 뜯은거 여기까지







	for (int i = 1; (i < dataLen + 1); i++)
	{
		if ((int)srcAddr[0] == 222 || (int)destAddr[0] == 222) {

			printf("%.2x ", ip_data[i - 1]);
			if ((i % LINE_LEN) == 0) printf("\n");
		}
	}





	if (protocol == 6) {//tcp
		int before = 14, flag = 0;
		int iplen = (int)pkt_data[14] % 16;

		before += iplen * 4;	//ethernet + ipv4 header

		int tcplen = (int)pkt_data[before + 12] / 16;
		u_char* http_data = (u_char*)malloc(sizeof(u_char) * (dataLen - tcplen * 4));

		/*printf("IP version : %d\n", version);
		printf("Header length : %d*32=%dbit\n", headerLen, headerLen * 32);
		printf("Type of service : %d\n", (int)TOS);
		printf("Total Packet Length : %dbyte\n", totalLenInt);
		printf("Fragmentation flags\n");
		printf("0 . . : always 0\n");
		printf(". %d . : may fragment field\n", flags[1]);
		printf(". . %d : more fragments field\n", flags[2]);
		printf("Fragments byte range : %d\n", fragmentOffset);
		printf("TTL : %d\n", (int)ttl);
		printf("Protocol : %d ( TCP-6, UDP-17 )\n", protocol);

		printf("Header checksum : %d\n", headerChecksum[1] + headerChecksum[0] * 256);*/
		//printf("Source IP addr : %d.%d.%d.%d\n", srcAddr[0], srcAddr[1], srcAddr[2], srcAddr[3]);
		//printf("Destination IP Addr : %d.%d.%d.%d\n", destAddr[0], destAddr[1], destAddr[2], destAddr[3]);







		u_char destPortNum[2]; //80 < 접속시도할때
		u_char srcPortNum[2]; //80 받을때 시도
		for (int i = 0; i < 2; i++)
		{
			srcPortNum[i] = ip_data[i];
			destPortNum[i] = ip_data[2 + i];
		}
		int destPort = (int)destPortNum[1];
		int srcPort = (int)srcPortNum[1];

		for (int i = 0; i < dataLen - (tcplen * 4); i++)
		{
			http_data[i] = ip_data[i + (tcplen * 4)];
		}

		////cout << destPort << "||" << srcPort << endl;
		//if (destPort == 80 || srcPort == 80 || (int)srcAddr[0] == 222 || (int)destAddr[0] == 222) {

		//	printf("tcpheaderlen = %dbyte \n", tcplen);
		//	printf("source port : %d\n", (int)pkt_data[before] * 196 + (int)pkt_data[before + 1]);
		//	printf("destination port: %d\n", (int)pkt_data[before + 2] * 196 + (int)pkt_data[before + 3]);
		//	//printf("Sequence Number (raw): %d\n", (int)pkt_data[before + 4] * 196 * 196 * 196 + (int)pkt_data[before + 5] * 196 * 196 + (int)pkt_data[before + 6] * 196 + (int)pkt_data[before + 7]);
		//	//printf("Acknowledgment Number (raw): %d\n", (int)pkt_data[before + 8] * 196 * 196 * 196 + (int)pkt_data[before + 9] * 196 * 196 + (int)pkt_data[before + 10] * 196 + (int)pkt_data[before + 11]);
		//	//flag = (int)pkt_data[before + 12] % 16 * 196 + (int)pkt_data[before + 13];
		//	//printf("Flags : 0x%.3x  %d\n", flag, flag);
		//	//pr_tcpflag(flag);
		//	//printf("Checksum : 0x%x%x\n", pkt_data[before + 16], pkt_data[before + 17]);

		//	print_http(header, http_data, dataLen);
		//}

		free(http_data);
	}
	else if (protocol == 17) { //udp
		//udp
		print_udp(ip_data);
		// dnsLen = dataLen - 8;
		u_char* dns_data = (u_char*)malloc(sizeof(u_char) * dataLen - 8);


		for (int i = 0; i < dataLen - 8; i++)
		{
			dns_data[i] = ip_data[i + 8];
		}



		/*printf("dns_data\n");
		for (int i = 1; (i < dnsLen+1); i++)
		{
			printf("%.2x ", dns_data[i - 1]);
			if ((i % LINE_LEN) == 0) printf("\n");
		}
		*/

		u_char destPortNum[2]; //80 < 접속시도할때
		u_char srcPortNum[2]; //80 받을때 시도
		for (int i = 0; i < 2; i++)
		{
			srcPortNum[i] = ip_data[i];
			destPortNum[i] = ip_data[2 + i];
		}
		int destPort = (int)destPortNum[1];
		int srcPort = (int)srcPortNum[1];
		if (destPort == 53 || srcPort == 53) {//DNS 는 53번 포트만 쓰는거
			//print_dns(header, dns_data);
		}
		free(dns_data);


	}


	free(data);
	free(ip_data);



}


void print_udp(u_char* data) {
	int idx = 0;
	u_char destPort[2];
	for (int i = 0; i < 2; i++)
	{
		destPort[i] = data[idx++];
	}
	int destPortInt = destPort[0] * 256 + destPort[1];
	u_char srcPort[2];
	for (int i = 0; i < 2; i++)
	{
		srcPort[i] = data[idx++];
	}
	int srcPortInt = srcPort[0] * 256 + srcPort[1];

	u_char len[2];
	for (int i = 0; i < 2; i++)
	{
		len[i] = data[idx++];
	}
	int lenInt = len[0] * 256 + len[1];

	u_char checksum[2];
	for (int i = 0; i < 2; i++)
	{
		checksum[i] = data[idx++];
	}
	int checksumInt = checksum[0] * 256 + checksum[1];

	printf("User Datagram Protocol\n");

	printf("Destination Port : %d\n", destPortInt);
	printf("Source Port : %d\n", srcPortInt);
	printf("Length : %d\n", lenInt);
	printf("checksum : %d\n", checksumInt);


}