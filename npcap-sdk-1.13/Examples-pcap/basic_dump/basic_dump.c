#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <pcap.h>
#include <stdio.h>
#include <time.h>
#ifdef _WIN32
#include <tchar.h>
#include <string.h>
BOOL LoadNpcapDlls()
{
	_TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return FALSE;
	}
	return TRUE;
}
#endif

/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
void tcpheader(const u_char *pkt_data);
void pr_tcpflag(int flag);
pcap_t* adhandle;
//int ii = 0;

int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;
	//pcap_t *adhandle;
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
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	
	/* Print the list */
	for(d=alldevs; d; d=d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
	
	if(i==0)
	{
		printf("\nNo interfaces found! Make sure Npcap is installed.\n");
		return -1;
	}
	
	printf("Enter the interface number (1-%d):",i);
	scanf("%d", &inum);
	
	if(inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	/* Jump to the selected adapter */
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
	
	/* Open the device */
	/* Open the adapter */
	if ((adhandle= pcap_open_live(d->name,	// name of the device
							 65536,			// portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
							 1,				// promiscuous mode (nonzero means promiscuous)
							 1000,			// read timeout
							 errbuf			// error buffer
							 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by Npcap\n", d->name);
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
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	

	/*if (ii > 5)
		pcap_breakloop(adhandle); //packet_handler멈추는 함수로 전역변수 ii값을 기준으로 멈추게 하였음(현재 모두 주석처리)
		*/

	if ((int)pkt_data[23] != 6)
		return ;
	
	

	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;

	/*
	 * unused parameters
	 */
	(VOID)(param);
	(VOID)(pkt_data);

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	ltime=localtime(&local_tv_sec);
	strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
	
	if (pkt_data[0] == 9*16 && pkt_data[1] == 14*16+8 && pkt_data[2] == 6*16 + 8 && pkt_data[3] == 2 * 16 + 9 && pkt_data[4] == 14*16+4 && pkt_data[5] == 16 + 11)
		printf("receiving packet\n");
	else
		printf("sending packet\n");	
	//수신자의 맥 주소에 따라 송신패킷인지 수신패킷인지 확인하는 구조, 파일 처음 컴파일시 해당 pc에 맞게 변경 필요
	
	printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
	tcpheader(pkt_data);

	printf("\n\n\n");
	//ii++;
}

void tcpheader(const u_char* pkt_data) {
	int before = 14, flag = 0;
	int iplen = (int)pkt_data[14] % 16;

	before += iplen * 4;	//ethernet + ipv4 header

	int tcplen = (int)pkt_data[before + 12] / 16;

	printf("tcpheaderlen = %dbyte \n", tcplen);
	printf("source port : %d\n", (int)pkt_data[before] * 196 + (int)pkt_data[before + 1]);
	printf("destination port: %d\n", (int)pkt_data[before + 2] * 196 + (int)pkt_data[before + 3]);
	printf("Sequence Number (raw): %d\n", (int)pkt_data[before + 4] * 196 * 196 * 196 + (int)pkt_data[before + 5] * 196 * 196 + (int)pkt_data[before + 6] * 196 + (int)pkt_data[before + 7]);
	printf("Acknowledgment Number (raw): %d\n", (int)pkt_data[before + 8] * 196 * 196 * 196 + (int)pkt_data[before + 9] * 196 * 196 + (int)pkt_data[before + 10] * 196 + (int)pkt_data[before + 11]);
	flag = (int)pkt_data[before + 12] % 16 * 196 + (int)pkt_data[before + 13];
	printf("Flags : 0x%.3x  %d\n", flag, flag);
	pr_tcpflag(flag);
	printf("Checksum : 0x%x%x\n", pkt_data[before + 16], pkt_data[before + 17]);
	for (int i = before; i < before + tcplen * 4; i++)
	{


		printf("%.2x ", pkt_data[i]);
		if ((i % 16) == 0) printf("\n");

	}

}

void pr_tcpflag(int flag) {
	char flags[] = "[000---------]";
	char flags2[] = "[000NCEUAPRSF]", tempc;
	int temp = flag, check = 256, idx = 4, i;
	for (i = 0; i < 9; i++) {
		if (temp / check >= 1) {
			flags[idx] = flags2[idx];
			temp = temp - check;
			//printf("temp : %d, check : %d ,%c\n",temp,  check, flags2[idx]);
			idx++;
		}
		else {
			idx++;
		}
		check = check / 2;

	}
	printf("%s\n",flags);
}

