
#include "stdafx.h"
#include "UI.h"
#include "interface_list.h"

void net_interface_view() {
	ClearUI();
	pcap_if_t* alldevs;
	pcap_if_t* d;
	char errbuf[PCAP_ERRBUF_SIZE + 1];


	WSADATA wsadata;
	int err = WSAStartup(MAKEWORD(2, 2), &wsadata);

	if (err != 0) {
		fprintf(stderr, "WSAStartup failed: %d\n", err);
		exit(1);
	}
	/* Load Npcap and its functions. */
	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		WSACleanup();
		exit(1);
	}


	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		WSACleanup();
		exit(1);
	}

	/* Scan the list printing every entry */
	for (d = alldevs; d; d = d->next)
	{
		ifprint(d);
	}

	/* Free the device list */
	pcap_freealldevs(alldevs);

	WSACleanup();
}

void basic_UI(int choice)
{
	ClearUI();
	//basic UI is NOT option
	char choice_list[UI_NUM::UI_COUNT-1][128];
	
	strcpy(choice_list[UI_NUM::INTERFACE_LIST_UI - 1], "INTERFACE_LIST");
	strcpy(choice_list[UI_NUM::UDP_UI - 1], "UDP_UI");
	strcpy(choice_list[UI_NUM::TEST_UI - 1], "TEST_UI");

	title_UI();

	for (int i = 0; i < (UI_NUM::UI_COUNT - 1); ++i) {
		cout << "[";
		if (choice == i+1) {
			cout << "¤·";
		}
		else {
			cout << "  ";
		}
		cout << "] " << choice_list[i] << endl;
	}
	cout << "CH : " << choice << endl;


}

void title_UI()
{
	cout << "==============================================================" << endl;
	cout << endl;
	cout << " :::==== :::  === :::  === :::====  :::====  :::===== :::==== " << endl;
	cout << " :::==== :::  === ::: ===  :::  === :::  === :::      :::  ===" << endl;
	cout << "   ===   ===  === ======   ===  === =======  ======   ========" << endl;
	cout << "   ===   ===  === === ===  ===  === === ===  ===      ===  ===" << endl;
	cout << "   ===    ======  ===  ===  ======  ===  === ======== ===  ===" << endl;
	cout << endl;
	cout << "==============================================================" << endl;
}

void ClearUI()
{
	unsigned long dw;
	FillConsoleOutputCharacter(GetStdHandle(STD_OUTPUT_HANDLE), ' ', 300 * 300, { 0, 0 }, &dw);
	COORD pos = { 0, 0 };
	SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), pos);
}