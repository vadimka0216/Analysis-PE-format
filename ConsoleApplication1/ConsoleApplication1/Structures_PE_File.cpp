#include "main.h"


Structures_PE_File::Structures_PE_File()
{
	this->InitVariables();
	SetFileBytes("myfile");
	this->InitStructures();
}
Structures_PE_File::Structures_PE_File(const char* nameFile)
{
	this->InitVariables();
	SetFileBytes(nameFile);
	this->InitStructures();
}

void Structures_PE_File::InitVariables(void)
{
	this->pSH = 0;
	this->FileBytes = 0;

	this->size_pNT = 0;
	this->count_pSH = 0;
	this->pDOS = 0;
	this->pNT = 0;

	this->FileSize = 0;
}

Structures_PE_File::~Structures_PE_File()
{
	this->ClearMemory();
}

void Structures_PE_File::ClearMemory(void)
{
	if (this->pSH != 0)
	{
		free(this->pSH);
		this->pSH = 0;
	}
	if (this->FileBytes != 0)
	{
		free(this->FileBytes);
		this->FileBytes = 0;
	}
}

void Structures_PE_File::SetFileBytes(const char* FileName)
{
	//HANDLE hFile = NULL;
	//DWORD dwFileSize = 0;
	FILE* hFile = 0;
	fopen_s(&hFile, FileName, "rb");
	//hFile = CreateFile((wchar_t*)FileName, GENERIC_ALL, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile)//(hFile != INVALID_HANDLE_VALUE)
	{
		fseek(hFile, 0, SEEK_END);
		FileSize=ftell(hFile);
		fseek(hFile, 0, SEEK_SET);
		this->FileBytes = (unsigned char*)malloc(FileSize);//LocalAlloc(LPTR, dwFileSize);
		if (this->FileBytes)
		{
			//DWORD dwBytesRead = 0;
			//ReadFile(hFile, FileBytes, dwFileSize, &dwBytesRead, NULL);
			if (!fread(this->FileBytes, FileSize, 1, hFile))
				this->ClearMemory();
		}

		fclose(hFile);
	}
	//return 0;
}

int Structures_PE_File::getIndexSection(const char* name)
{
	PIMAGE_SECTION_HEADER* p = this->pSH;
	WORD size = this->count_pSH;
	for (int i = 0; i < size; i++)
	{
		bool flag = true;
		for (int j = 0; j < sizeof p[i]->Name; j++)
			if (name[j] != p[i]->Name[j])
			{
				flag = false;
				break;
			}
		if (flag)
			return i;
	}
	return -1;
}
/*
int Structures_PE_File::getIndexRdata()//(PIMAGE_SECTION_HEADER* p, WORD size)
{
	return getIndexSection(this->pSH, this->count_pSH, ".rdata");
}
*/
int Structures_PE_File::getRVA(int VA)
{
	int result = 0;
	if (!this->CheckError())
	{
		for (int i = 0; i < count_pSH - 1; i++)
			if (pSH[i]->VirtualAddress <= VA&&VA<pSH[i + 1]->VirtualAddress)//находим RVA
			{
				result = VA - pSH[i]->VirtualAddress + pSH[i]->PointerToRawData;
				break;
			}
	}
	return result;
}

void Structures_PE_File::InitStructures(void)
{
	if (this->FileBytes)
	{
		unsigned char* pvBuffer = this->FileBytes;

		pDOS = (PIMAGE_DOS_HEADER)pvBuffer;
		//InfoDOS_Header(pDOS);
		pNT = (PIMAGE_NT_HEADERS)(pvBuffer + pDOS->e_lfanew);
		//InfoNT_Header(pNT);
		long size_pNT = sizeof(pNT->FileHeader) + sizeof(pNT->OptionalHeader) + sizeof(pNT->Signature);
		if (pvBuffer[pDOS->e_lfanew + size_pNT + 1] == 0)
		{
			for (; pvBuffer[pDOS->e_lfanew + size_pNT + 1] == 0; size_pNT++);//+ other;//+16 нулей
			size_pNT++;
		}
		this->count_pSH = pNT->FileHeader.NumberOfSections;
		pSH = (PIMAGE_SECTION_HEADER*)malloc(count_pSH*sizeof(PIMAGE_SECTION_HEADER));

		if (pSH != 0)
		{

			for (int i = 0; i < count_pSH; i++)
				pSH[i] = (PIMAGE_SECTION_HEADER)(pvBuffer + pDOS->e_lfanew + size_pNT + size_pSH*i);
			//InfoSections_Header(pSH, pNT->FileHeader.NumberOfSections);
			//int i_rdata = this->getIndexRdata();


		}
		//free(pSH);
	}
}


bool Structures_PE_File::CheckError(void)//for public methods
{
	return !(this->FileBytes && this->pSH&&this->pDOS&&this->pNT);
}

void Structures_PE_File::InfoDOS_Header()//PIMAGE_DOS_HEADER p)
{
	if (!this->CheckError())
	{
		PIMAGE_DOS_HEADER p = this->pDOS;
		printf("\n\n================InfoDOS_Header================\n\n");
		printf("e_magic: %d, e_cblp: %d, e_cp: %d, e_crlc: %d, e_cparhdr: %d, e_minalloc: %d\n",
			p->e_magic, p->e_cblp, p->e_cp, p->e_crlc, p->e_cparhdr, p->e_minalloc);
		printf("e_maxalloc: %d, e_ss: %d, e_csum: %d, e_csum: %d, e_ip: %d, e_cs: %d\n",
			p->e_maxalloc, p->e_ss, p->e_sp, p->e_csum, p->e_ip, p->e_cs);
		printf("e_lfarlc: %d, e_ovno: %d, e_oeminfo: %d\n", p->e_lfarlc, p->e_ovno, p->e_oemid, p->e_oeminfo);
		printf("e_res: ");
		for (int i = 0; i < sizeof(p->e_res) / sizeof(WORD); i++)
			printf(" %d ", p->e_res[i]);
		printf("\ne_res2: ");
		for (int i = 0; i < sizeof(p->e_res2) / sizeof(WORD); i++)
			printf(" %d ", p->e_res2[i]);
		printf("\ne_lfanew: %d\n", p->e_lfanew);
		printf("=============================================\n");
	}
}
void Structures_PE_File::InfoNT_Header()//PIMAGE_NT_HEADERS p)
{
	if (!this->CheckError())
	{
		printf("\n\n================InfoNT_Header================\n\n");
		printf("Signature: %X\n", this->pNT->Signature);
		printf("FileHeader:\n Characteristics: %d, Machine: %d, NumberOfSections: %d, NumberOfSymbols: %d\n", 
			pNT->FileHeader.Characteristics, pNT->FileHeader.Machine, pNT->FileHeader.NumberOfSections, pNT->FileHeader.NumberOfSymbols);
		printf("PointerToSymbolTable: %d, SizeOfOptionalHeader: %d, TimeDateStamp: %d\n", 
			pNT->FileHeader.PointerToSymbolTable, pNT->FileHeader.SizeOfOptionalHeader, pNT->FileHeader.TimeDateStamp);
		printf("\nOptionalHeader:\n");
		IMAGE_OPTIONAL_HEADER op = pNT->OptionalHeader;
		printf("AddressOfEntryPoint: %d, BaseOfCode: %d, BaseOfData: %d, CheckSum: %d, DataDirectory: %d\n", 
			op.AddressOfEntryPoint, op.BaseOfCode, op.BaseOfData, op.CheckSum, op.DataDirectory);
		printf("DllCharacteristics: %d, FileAlignment: %d, ImageBase: %d, LoaderFlags: %d, Magic: %d\n",
			op.DllCharacteristics, op.FileAlignment, op.ImageBase, op.LoaderFlags, op.Magic);
		printf("SizeOfCode: %d, SizeOfHeaders: %d, SizeOfHeapCommit: %d, SizeOfImage: %d,\n SizeOfInitializedData: %d, SizeOfStackCommit: %d\n", 
			op.SizeOfCode, op.SizeOfHeaders, op.SizeOfHeapCommit, op.SizeOfImage, op.SizeOfInitializedData, op.SizeOfStackCommit);
		printf("SizeOfStackReserve: %d, SizeOfUninitializedData: %d, Subsystem: %d, Win32VersionValue: %d\n", 
			op.SizeOfStackReserve, op.SizeOfUninitializedData, op.Subsystem, op.Win32VersionValue);
		printf("=============================================\n");
	}
}
void Structures_PE_File::InfoSections_Header()//PIMAGE_SECTION_HEADER* p, WORD size)
{
	if (!this->CheckError())
	{
		printf("\n\n================InfoSections_Header================\n\n");
		if (pSH != 0)
		{
			for (int i = 0; i < this->count_pSH; i++)
			{
				std::string str;
				for (int j = 0; j < sizeof pSH[i]->Name; j++)
					str += pSH[i]->Name[j]; str += '\0';

				printf("| Section %d | name: %s, VirtualAddress: %d, SizeOfRawData: %d, PointerToRelocations: %d\n", 
					i, str.c_str(), pSH[i]->VirtualAddress, pSH[i]->SizeOfRawData, pSH[i]->PointerToRelocations);
				printf("PointerToRawData: %d, PointerToLinenumbers: %d, NumberOfRelocations: %d, NumberOfLinenumbers: %d\n",
					pSH[i]->PointerToRawData, pSH[i]->PointerToLinenumbers, pSH[i]->NumberOfRelocations, pSH[i]->NumberOfLinenumbers);
				printf("Misc: %d, Characteristics: %d", pSH[i]->Misc, pSH[i]->Characteristics);

				printf("\n\n");
			}
		}
		printf("=============================================\n");
	}
}


void Structures_PE_File::InfoImport(void)
{
	if (!this->CheckError())
	{
		printf("\n\n================InfoImport================\n\n");
		unsigned char* pvBuffer = this->FileBytes;
		int size = pNT->OptionalHeader.DataDirectory[1].Size;
		int VA = pNT->OptionalHeader.DataDirectory[1].VirtualAddress;
		if (VA != 0 && size != 0)
		{
			int size = pNT->OptionalHeader.DataDirectory[1].Size;
			int VA = pNT->OptionalHeader.DataDirectory[1].VirtualAddress;
			int RVA = this->getRVA(VA);
			if (RVA > 0 && RVA < this->FileSize)
			{
				int sizeImport = sizeof IMAGE_IMPORT_DESCRIPTOR;
				for (int i = 0; i < size - sizeImport; i += sizeImport)
				{

					PIMAGE_IMPORT_DESCRIPTOR import = (PIMAGE_IMPORT_DESCRIPTOR)(pvBuffer + RVA + i); // + IMAGE_THUNK_DATA
					if (import->Characteristics != 0 || import->FirstThunk != 0 || import->ForwarderChain != 0 || import->Name != 0 || import->OriginalFirstThunk != 0 || import->TimeDateStamp != 0)
					{
						printf("Name dll: %s", pvBuffer + this->getRVA(import->Name));
						PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)(pvBuffer + this->getRVA(import->FirstThunk));
						if (thunk->u1.Function)
						{
							printf("  ; names func: \n");
							while (thunk->u1.Function)
							{
								int RVA_func = this->getRVA(thunk->u1.Function);
								if (RVA_func > 0 && RVA_func < this->FileSize)
								{
									PIMAGE_IMPORT_BY_NAME func = (PIMAGE_IMPORT_BY_NAME)(pvBuffer + this->getRVA(thunk->u1.Function));
									printf("%s, ", func->Name);
								}
								thunk++;
							}
						}
						printf("\n");
					}
					else
					{
						break;
					}
				}
			}
		}

		printf("=============================================\n");
	}
}

void Structures_PE_File::InfoResource(int offset, int size)
{
	unsigned char* pvBuffer = this->FileBytes;
	PIMAGE_RESOURCE_DIRECTORY pDirectory;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pDirEntry;
	for (int i = 1; i <= 3; i++)
	{
		if (this->FileSize > (offset + sizeof IMAGE_RESOURCE_DIRECTORY))
		{
			pDirectory = (PIMAGE_RESOURCE_DIRECTORY)(pvBuffer + offset);
			printf("\nDirectory %d: Characteristics %d; MajorVersion %d; MinorVersion %d, NumberOfIdEntries %d; NumberOfNamedEntries %d; TimeDateStamp %d", i,
				pDirectory->Characteristics, pDirectory->MajorVersion, pDirectory->MinorVersion, pDirectory->NumberOfIdEntries,
				pDirectory->NumberOfNamedEntries, pDirectory->TimeDateStamp);
		}
		size -= sizeof IMAGE_RESOURCE_DIRECTORY; offset += sizeof IMAGE_RESOURCE_DIRECTORY;

		if (this->FileSize > (offset + sizeof IMAGE_RESOURCE_DIRECTORY_ENTRY))
		{
			pDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pvBuffer + offset);
			printf("\nDir Entry %d: DataIsDirectory %d; Id %d; Name %d; NameIsString %d; NameOffset %d, OffsetToData %d; OffsetToDirectory %d",
				i, pDirEntry->DataIsDirectory, pDirEntry->Id, pDirEntry->Name, pDirEntry->NameIsString,
				pDirEntry->NameOffset, pDirEntry->OffsetToData, pDirEntry->OffsetToDirectory);
		}
		size -= sizeof IMAGE_RESOURCE_DIRECTORY_ENTRY; offset += sizeof IMAGE_RESOURCE_DIRECTORY_ENTRY;
	}
	if (this->FileSize > (offset + sizeof IMAGE_RESOURCE_DATA_ENTRY))
	{
		PIMAGE_RESOURCE_DATA_ENTRY pDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)(pvBuffer + offset);
		size -= sizeof IMAGE_RESOURCE_DATA_ENTRY; offset += sizeof IMAGE_RESOURCE_DATA_ENTRY;
		printf("\nInfoDataEntry: CodePage %d; OffsetToData %d; Reserved %d; Size %d", pDataEntry->CodePage, pDataEntry->OffsetToData,
			pDataEntry->Reserved, pDataEntry->Size);
	}
	//pDataEntry->OffsetToData == RVA RESOURCE DATA (offset =offset Section + RVA RESOURCE DATA - RVA Section);  
	printf("\nRESOURCE DATA:\n");
	for (int i = offset; i <= offset + size&&i < this->FileSize; i++)
		printf("%c", pvBuffer[i]);
	/*if (offset > 0 && offset < this->FileSize)
	{

	PIMAGE_RESOURCE_DIRECTORY pRSRC = (PIMAGE_RESOURCE_DIRECTORY)(pvBuffer + offset);
	int d;
	}*/
}

void Structures_PE_File::InfoRSRC(void)
{
	if (!this->CheckError())
	{
		printf("\n\n================InfoSectionResource(.RSRC)================\n\n");
		int index=this->getIndexSection(".rsrc");
		if (index >= 0)
		{
			if ((pSH[index]->Characteristics & 0x40) == 0x40)//если секция является инициалищированными данными
			{
				int offset = pSH[index]->PointerToRawData;
				int size = pSH[index]->SizeOfRawData;
				this->InfoResource(offset, size);
			}
		}
		printf("\n=============================================\n");
	}
}
void Structures_PE_File::InfoRELOC(void)
{
	if (!this->CheckError())
	{
		printf("\n\n================InfoSectionRELOCATION(.reloc)================\n\n");

		int index = this->getIndexSection(".reloc");
		if (index >= 0)
		{
			if ((pSH[index]->Characteristics & 0x02000000) == 0x02000000)//если секция является IMAGE_SCN_MEM_DISCARDABLE (выбрасываемым элементом)
			{
				int offset = pSH[index]->PointerToRawData;
				int size = pSH[index]->SizeOfRawData;
				//this->InfoResource(offset, size);
				/*for (int i = offset; i <= offset + size&&i < this->FileSize; i++)
					printf("%c", this->FileBytes[i]);*/
				int i = 0;
				while (offset > 0 && (offset + 8) < this->FileSize)
				{
					i++;
					PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)(this->FileBytes + offset);
					if (pReloc->SizeOfBlock != 0)
						offset += pReloc->SizeOfBlock;//size -= pReloc->SizeOfBlock;
					else if (pReloc->VirtualAddress == 0)
						break;
					else
						offset += sizeof IMAGE_BASE_RELOCATION;
					printf("Reloc %d: VA 0x%x; size: %d\n", i, pReloc->VirtualAddress, pReloc->SizeOfBlock);
				}
			}
		}
		printf("\n=============================================\n");
	}
}

void Structures_PE_File::InfoAll(void)
{
	if (!this->CheckError())
	{
		this->InfoDOS_Header();
		this->InfoNT_Header();
		this->InfoSections_Header();
		this->InfoImport();
		this->InfoRSRC();
		this->InfoRELOC();
	}
	else
	{
		printf("Get unknown error!\n");
	}
}