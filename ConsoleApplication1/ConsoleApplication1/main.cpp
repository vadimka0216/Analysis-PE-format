//#define _CRT_SECURE_NO_WARNINGS
#include "Structures_PE_File.h"


/*
1. ������� ���� � ����� � ������
2. ������� ���������� � ���������� ����� (DOS-Header, NT-Header)
3. ������� ���������� � ������� �����
4. ������� ���������� � ������������� �������� � �����������
5. ������� ���������� � ������� ��������
6. ������� ���������� � ������� ������������ ���������
//ctrl+shift+space//�������� ���������� ��������� �������
//ctrsl+shift+a//������� ����, item
*/


int main(int count, char** args)
{
	setlocale(LC_ALL, "RUS");
	
	Structures_PE_File* object = new Structures_PE_File("OnlineParser1.exe");//("myfile");//("test.exe");//("OnlineParser1.exe");
	object->InfoAll();
	system("pause");
	delete object; object=0;
	return 0;
}