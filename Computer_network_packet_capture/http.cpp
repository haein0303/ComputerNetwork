#include "stdafx.h"
#include "http.h"


#include "stdafx.h"
#include "dns.h"
#include "UI.h"

int dnsLen2;
static int check_ip[4] = { 222,117,38,218 }; //전역이긴한데 이 파일 안에서만 쓸려고함
static char check;
static char htmlView;

int http_main() {
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

	ClearUI();
	
	cout << "IP를 지정하시겠습니까? (y/n) ";
	scanf(" %c", &check);
	if (check == 'y') {
		cout << "defaul ip를 사용하시겠습니까? (haein0303.iptime.org) (y/n) ";
		char tmp_check;
		scanf(" %c", &tmp_check);
		if (tmp_check == 'n') {
			cout << "접속할 http 사이트의 아이피를 입력해주세요" << endl;
			scanf(" %d.%d.%d.%d", &check_ip[0], &check_ip[1], &check_ip[2], &check_ip[3]);
		}		
	}
	cout << "데이터 필드를 보시겠습니까? (y/n)";
	scanf(" %c", &htmlView);
	ClearUI();


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
	pcap_loop(adhandle, 0, http_packet_handler, NULL);

	pcap_close(adhandle);
	return 0;
}

void http_packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
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

	http_ip_layer(header, pkt_data);

}

void http_ip_layer(const pcap_pkthdr* header, const u_char* pkt_data) {

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

	/*for (int i = 1; (i < dataLen + 1); i++)
	{
		if ((int)srcAddr[0] == 222 || (int)destAddr[0] == 222) {

			printf("%.2x ", ip_data[i - 1]);
			if ((i % LINE_LEN) == 0) printf("\n");
		}
	}*/

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
		if (destPort == 80 || srcPort == 80) {
			if (check == 'y') {
				bool scr_toggle = true;
				bool dest_toggle = true;
				for (int i = 0; i < 4; i++) {
					if((int)srcAddr[i] != check_ip[i]) scr_toggle = false;
					if ((int)destAddr[i] != check_ip[i]) dest_toggle = false;
				}
				if(scr_toggle || dest_toggle) {

					print_http(header, http_data, dataLen);
				}
			}
		}
		
		free(http_data);
	}
	else if (protocol == 17) { //udp
		//udp
		dnsLen2 = dataLen - 8;
		u_char* dns_data = (u_char*)malloc(sizeof(u_char) * dataLen - 8);

		for (int i = 0; i < dataLen - 8; i++)
		{
			dns_data[i] = ip_data[i + 8];
		}



		/*printf("dns_data\n");
		for (int i = 1; (i < dnsLen2+1); i++)
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


	}

	free(data);
	free(ip_data);
}

void print_http(const pcap_pkthdr* header, u_char* data, int dataLen) {
	u_char endLineChecker[2];
	endLineChecker[0] = '\r';
	endLineChecker[1] = '\n';
	bool empty_check = false;

	string line;
	vector<string> httpheader;
	vector<string> htmlcode;
	int i = 0;
	cout << "DL " << dataLen << endl;

	while (i < (dataLen - 1)) {
		if (data[i] == endLineChecker[0] && data[i + 1] == endLineChecker[1]) {
			if (!empty_check) {
				if (data[i + 2] == endLineChecker[0] && data[i + 3] == endLineChecker[1]) {
					empty_check = true;
				}
				httpheader.push_back(line);
			}
			else {
				htmlcode.push_back(line);
			}			
			line.clear();
		}
		else {
			line.push_back(data[i]);
		}
		i++;
	}

	cout << "전체 크기 : " << httpheader.size() << endl;
	for (auto a : httpheader) {
		cout << a << endl;
	}
	if (htmlView == 'y') {
		for (auto a : htmlcode) {
			cout << a << endl;
		}
	}

	return;
}

