
#include "stdafx.h"
#include "UI.h"



void basic_UI(int choice)
{
	ClearUI();
	//basic UI is NOT option
	char choice_list[UI_NUM::UI_COUNT-1][128];
	
	strcpy(choice_list[UI_NUM::TCP_UI - 1], "TCP_UI");
	strcpy(choice_list[UI_NUM::UDP_UI - 1], "UDP_UI");
	strcpy(choice_list[UI_NUM::DNS_UI - 1], "DNS_UI");
	strcpy(choice_list[UI_NUM::HTTP_UI - 1], "HTTP_UI");

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