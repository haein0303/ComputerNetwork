#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "stdafx.h"



#define LINE_LEN 16




using namespace std;



/* prototype of the packet handler */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
void ip_layer(const pcap_pkthdr* ,const u_char*);
void print_dns(const pcap_pkthdr* header, u_char*);
int main()
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
	pcap_loop(adhandle, 0, packet_handler, NULL);

	pcap_close(adhandle);
	return 0;
}


/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
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

	ip_layer(header, pkt_data);

}
int dnsLen;
void ip_layer(const pcap_pkthdr* header, const u_char* pkt_data) {

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
	int totalLenInt = totalLen[0]*256 + totalLen[1];
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
	flags[1] = (flag & 2)?1:0;
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
	int dataLen = totalLenInt - (headerLen)*4;
	u_char* ip_data = (u_char*)malloc(sizeof(u_char) * (dataLen));
	for (int i = 0; i < dataLen; i++)
	{
		ip_data[i] = data[headerLen*4+i];
	}
	//이더넷 뜯은거 여기까지


	

	

	
	for (int i = 1; (i < dataLen + 1); i++)
	{
		if ((int)srcAddr[0] == 222 || (int)destAddr[0] == 222){
			
			printf("%.2x ", ip_data[i - 1]);
			if ((i % LINE_LEN) == 0) printf("\n");
		}
	}
	
	


	if (protocol == 6) {//tcp
		int before = 14, flag = 0;
		int iplen = (int)pkt_data[14] % 16;

		before += iplen * 4;	//ethernet + ipv4 header

		int tcplen = (int)pkt_data[before + 12] / 16;
		u_char* http_data = (u_char*)malloc(sizeof(u_char) * (dataLen - tcplen*4));
		
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
		
		for (int i = 0; i < dataLen - (tcplen*4); i++)
		{
			http_data[i] = ip_data[i + (tcplen * 4)];
		}

		//cout << destPort << "||" << srcPort << endl;
		if (destPort == 80 || srcPort == 80 || (int)srcAddr[0] == 222 || (int)destAddr[0] == 222) {
			
			printf("tcpheaderlen = %dbyte \n", tcplen);
			printf("source port : %d\n", (int)pkt_data[before] * 196 + (int)pkt_data[before + 1]);
			printf("destination port: %d\n", (int)pkt_data[before + 2] * 196 + (int)pkt_data[before + 3]);
			//printf("Sequence Number (raw): %d\n", (int)pkt_data[before + 4] * 196 * 196 * 196 + (int)pkt_data[before + 5] * 196 * 196 + (int)pkt_data[before + 6] * 196 + (int)pkt_data[before + 7]);
			//printf("Acknowledgment Number (raw): %d\n", (int)pkt_data[before + 8] * 196 * 196 * 196 + (int)pkt_data[before + 9] * 196 * 196 + (int)pkt_data[before + 10] * 196 + (int)pkt_data[before + 11]);
			//flag = (int)pkt_data[before + 12] % 16 * 196 + (int)pkt_data[before + 13];
			//printf("Flags : 0x%.3x  %d\n", flag, flag);
			//pr_tcpflag(flag);
			//printf("Checksum : 0x%x%x\n", pkt_data[before + 16], pkt_data[before + 17]);

			print_http(header, http_data, dataLen);
		}

		free(http_data);
	}
	else if(protocol==17){ //udp
		//udp
		dnsLen = dataLen - 8;
		u_char* dns_data = (u_char*)malloc(sizeof(u_char) * dataLen - 8);
		
		for (int i = 0; i < dataLen-8; i++)
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
		if (destPort == 53 || srcPort==53) {//DNS 는 53번 포트만 쓰는거
			//print_dns(header, dns_data);
		}
		
		
	}
	
		free(data);
		free(ip_data);
		
	

}

//
void print_http(const pcap_pkthdr* header, u_char* data, int dataLen) {
	u_char endLineChecker[2];
	endLineChecker[0] = '\r';
	endLineChecker[1] = '\n';
	
	string line;
	vector<string> httpheader;
	int i = 0;
	cout << (int)data[0] << "  " << (int)data[3] << "  " << (int)data[4] << "  " << (int)data[5] << "  " << (int)data[1] << " DL" << dataLen << endl;

	while (i < (dataLen-1)) {
		if (data[i] == endLineChecker[0] && data[i + 1] == endLineChecker[1]) {
			//cout << "들어왔니?" << endl;
			httpheader.push_back(line);
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

	return;
}


void print_dns(const pcap_pkthdr* header, u_char* data) {
	
	int idx = 0;
	u_char transactionId[2];
	for (int i = 0; i < 2; i++)
	{
		transactionId[i] = data[idx++];
	}
	int transactionIdInt = transactionId[0] * 256 + transactionId[1];
	u_char flag[2];
	for (int i = 0; i < 2; i++)
	{
		flag[i] = data[idx++];
	}
	u_char qCount[2];
	for (int i = 0; i < 2; i++)
	{
		qCount[i] = data[idx++];
	}
	int qCountInt = qCount[0] * 256 + qCount[1];
	u_char aCount[2];
	for (int i = 0; i < 2; i++)
	{
		aCount[i] = data[idx++];
	}
	int aCountInt = aCount[0] * 256 + aCount[1];

	u_char nameServerCount[2];
	for (int i = 0; i < 2; i++)
	{
		nameServerCount[i] = data[idx++];
	}
	int nameServerCountInt = nameServerCount[0] * 256 + nameServerCount[1];

	u_char etcRecordCounter[2];
	for (int i = 0; i < 2; i++)
	{
		etcRecordCounter[i] = data[idx++];
	}
	int etcRecordCounterInt = etcRecordCounter[0] * 256 + etcRecordCounter[1];

	int flags[16];
	int mask = 32786;
	unsigned short flagInt = flag[0] * 256 + flag[1];
	for (int i = 0; i < 16; i++)
	{
		flags[i] = (flagInt & mask) ? 1 : 0;
		mask = mask >> 1;
	}
	int hostNameLen = 0;
	int delimeter = data[idx++];
	
	
	
	string hostName;
	
	while (delimeter != 0) {
		for (int i = 0; i < delimeter; ++i) {
			char c[2];
			c[0]= data[idx + i];
			c[1] = '\0';
			string s(c);
			hostName = hostName.append(s);
		}
		hostName.append(".");
		idx = idx + delimeter;
		delimeter = data[idx++];
	}
	u_char qType[2];
	for (int i = 0; i < 2; i++)
	{
		qType[i] = data[idx++];
	}
	int qTypeInt = qType[0] * 256 + qType[1];
	u_char qClass[2];
	for (int i = 0; i < 2; i++)
	{
		qClass[i] = data[idx++];
	}
	int qClassInt = qClass[0] * 256 + qClass[1];

	

	printf("Transaction ID : %d\n", transactionIdInt);
	printf("Flags\n");
	printf("%d . . . . . . . . . . . . . . . : QR bit\n", flags[0]);
	printf(". %d . . . . . . . . . . . . . . : Opcode bit\n", flags[1]);
	printf(". . %d . . . . . . . . . . . . . : Opcode bit\n", flags[2]);
	printf(". . . %d . . . . . . . . . . . . : Opcode bit\n", flags[3]);
	printf(". . . . %d . . . . . . . . . . . : Opcode bit\n", flags[4]);
	printf(". . . . . %d . . . . . . . . . . : AA bit\n", flags[5]);
	printf(". . . . . . %d . . . . . . . . . : TC bit\n", flags[6]);
	printf(". . . . . . . %d . . . . . . . . : RD bit\n", flags[7]);
	printf(". . . . . . . . %d . . . . . . . : RA bit\n", flags[8]);
	printf(". . . . . . . . . %d . . . . . . : Reserved bit\n", flags[9]);
	printf(". . . . . . . . . . %d . . . . . : Reserved bit\n", flags[10]);
	printf(". . . . . . . . . . . %d . . . . : Reserved bit\n", flags[11]);
	printf(". . . . . . . . . . . . %d . . . : rCode bit\n", flags[12]);
	printf(". . . . . . . . . . . . . %d . . : rCode bit\n", flags[13]);
	printf(". . . . . . . . . . . . . . %d . : rCode bit\n", flags[14]);
	printf(". . . . . . . . . . . . . . . %d : rCode bit\n", flags[15]);
	printf("%d : Question count\n", qCountInt);
	printf("%d : Answer count\n", aCountInt);
	printf("%d : nameServer count\n", nameServerCountInt);
	printf("%d : Additional count\n", etcRecordCounterInt);

	cout << "Host name : " << hostName << "\n";
	printf("Query type : %d\n", qTypeInt);
	printf("Query class : % d\n", qClassInt);

	// response
	if (flags[1] == 1) {
		u_char TTL[4];
		for (int i = 0; i < 4; i++)
		{
			TTL[i] = data[idx++];
		}
		int TTLInt = TTL[0] * 256 + TTL[1];
		u_char dataLen[2];
		for (int i = 0; i < 2; i++)
		{
			dataLen[i] = data[idx++];
		}
		int dataLenInt = dataLen[0] * 256 + dataLen[1];
		
		printf("TTL : %d\n", TTLInt);
		printf("Resource data len : %d\n", dataLenInt);
		for (int i = 0; idx+i < dataLenInt; i++)
		{
			printf("%.2x", data[idx]);
		}

	}
	



	struct tm* ltime;
	char timestr[16];
	time_t local_tv_sec;
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
	printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
	

	

}
