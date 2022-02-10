#pragma once
#ifndef Structures_PE_File_H
#define Structures_PE_File_H

#include <Windows.h>
#include <stdio.h>
#include <locale>
#include <string>

class Structures_PE_File
{

private:
	const int size_pSH = 40;

	unsigned char* FileBytes;
	long FileSize;
	PIMAGE_DOS_HEADER pDOS;
	PIMAGE_NT_HEADERS pNT;
	long size_pNT;
	PIMAGE_SECTION_HEADER* pSH;
	int count_pSH;

public:
	Structures_PE_File();
	Structures_PE_File(const char* nameFile);
	~Structures_PE_File();
	void InfoAll(void);
	void InfoDOS_Header(void);
	void InfoNT_Header(void);
	void InfoSections_Header(void);
	void InfoImport(void);
	void InfoRSRC(void);
	void InfoRELOC(void);

private:
	void ClearMemory(void);
	/*unsigned char**/ void SetFileBytes(const char* nameFile);
	void InitStructures(void);
	bool CheckError(void);
	void InitVariables(void);

	int getIndexSection(const char* name);
	//int getIndexRdata();
	int getRVA(int VA);

	void InfoResource(int offset, int size);
};

#endif