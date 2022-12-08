#include "stdafx.h"
#include "UI.h"
#include "dns.h"
#include "http.h"
#include "tcp.h"
#include "udp.h"

using namespace std;


int main()
{
	int choice = 1;
	int SceneChoice = 0;
	char key = 0;
	int allcount = UI_NUM::UI_COUNT - 1;

	while (1) {
		switch (SceneChoice) {
		case UI_NUM::BASIC_UI:
			switch (key) {
			case KEY_UP:
				choice = (allcount + choice -2) % allcount +1;
				break;
			case KEY_DOWN:
				choice = choice % allcount + 1;
				break;
			case KEY_ENTER:
				SceneChoice = choice;
				ClearUI();
				continue;
				break;
			}
			basic_UI(choice);
			break;
		case UI_NUM::TCP_UI:
			tcp_main();
			break;
		case UI_NUM::UDP_UI:
			udp_main();
			break;
		case UI_NUM::DNS_UI:
			dns_main();
			break;
		case UI_NUM::HTTP_UI:
			http_main();
			break;
		}
		//Å°ÀÔ·Â
		key = _getch();
		if (key == -32) {
			key = _getch();
		}
	}
}





