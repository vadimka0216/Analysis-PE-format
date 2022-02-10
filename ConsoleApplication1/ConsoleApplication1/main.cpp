//#define _CRT_SECURE_NO_WARNINGS
#include "Structures_PE_File.h"


/*
1. Считать файл с диска в память
2. Вывести информацию о заголовках файла (DOS-Header, NT-Header)
3. Вывести информацию о секциях файла
4. Вывести информацию о импортируемых функциях и библиотеках
5. Вывести информацию о секциях ресурсов
6. Вывести информацию о секциях перемещаемых элементов
//ctrl+shift+space//показать формальные параметры функции
//ctrsl+shift+a//создать файл, item
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