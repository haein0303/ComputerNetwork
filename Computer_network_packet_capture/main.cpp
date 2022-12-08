#include "stdafx.h"
#include "interface_list.h"
#include "UI.h"
#include "UDP_dump.h"
#include "pcap_filter.h"
#include "basic_dump.h"

pcap_if_t* d;

int main()
{
	char key = 0;
	int ui_num = 0;
	int basic_ui_choice = 1;
	
	while (1) {
		switch (ui_num) {
		case UI_NUM::BASIC_UI:
			switch (key) {
			case KEY_UP:
				basic_ui_choice = (basic_ui_choice+1)  % (UI_NUM::UI_COUNT-1) + 1;
				break;
			case KEY_DOWN:
				basic_ui_choice = basic_ui_choice % (UI_NUM::UI_COUNT - 1) + 1;
				break;
			case KEY_ENTER:
				ui_num = basic_ui_choice;
				break;
			case '1':
				ui_num = 1;
				break;
			}
			basic_UI(basic_ui_choice);
			break;
		case UI_NUM::INTERFACE_LIST_UI:
			net_interface_view();
			switch (key) {
			case KEY_BACKSPACE:
				ui_num = 0;
				break;
			}
			break;
		case UI_NUM::UDP_UI:
			ClearUI();
			UDP_main();
			break;
		case UI_NUM::BASIC_DUMP_UI:
			basic_dump_main();
			break;
		}		
		key = _getch();
		if (key == 0xE0 || key == 0) {   //�Է¹��� ���� Ȯ��Ű �̸�
			key = _getch();
			fflush(stdin);
		}		
	}
	
	
	

	//net_interface_view();
	return 0;
}



