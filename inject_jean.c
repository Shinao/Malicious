/**
 ** peviewimagedosheader.c
 */

#include <windows.h>
#include <stdio.h>

void	PrintImageSectionHeader(PIMAGE_SECTION_HEADER pImageSectionHeader)
{
    printf("Name: %s\n", pImageSectionHeader->Name);
    printf("Misc: %ld\n", pImageSectionHeader->Misc);
    printf("Misc VirtualSize: %ld\n", pImageSectionHeader->Misc.VirtualSize);
    printf("VirtualAddress: %ld\n", pImageSectionHeader->VirtualAddress);
    printf("SizeOfRawData: %ld\n", pImageSectionHeader->SizeOfRawData);
    printf("PointerToRawData: %ld\n", pImageSectionHeader->PointerToRawData);
    printf("PointerToRelocations: %ld\n", pImageSectionHeader->PointerToRelocations);
    printf("PointerToLinenumbers: %ld\n", pImageSectionHeader->PointerToLinenumbers);
    printf("NumberOfRelocations: %ld\n", pImageSectionHeader->NumberOfRelocations);
    printf("NumberOfLinenumbers: %ld\n", pImageSectionHeader->NumberOfLinenumbers);
    printf("Characteristics: %ld\n\n", pImageSectionHeader->Characteristics);
}

int			main(int argc, char **argv) 
{
	PIMAGE_DOS_HEADER			pImageDosHeader;
	PIMAGE_NT_HEADERS			pImageNtHeaders;
	PIMAGE_OPTIONAL_HEADER		pImageOptionalHeader;
	PIMAGE_SECTION_HEADER		pImageSectionHeader;
	PIMAGE_FILE_HEADER			pImageFileHeader;
	HANDLE		hFile;
	HANDLE		hMapObject;
	PUCHAR				 	uFileMap;

	if (argc < 2)
		return (-1);

	if (!(hFile = CreateFile(argv[1], GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, 0)))
		return (-1);
	
	if (!(hMapObject = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL)))
		return (-1);

	if (!(uFileMap = MapViewOfFile(hMapObject, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0)))
		return (-1);
	
	pImageDosHeader = (PIMAGE_DOS_HEADER) uFileMap ;	
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return (-1);

	pImageNtHeaders = (PIMAGE_NT_HEADERS) ((PUCHAR) uFileMap + pImageDosHeader->e_lfanew);
	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
		return (-1);

	
	pImageFileHeader = (PIMAGE_FILE_HEADER) &(pImageNtHeaders->FileHeader);
	pImageOptionalHeader = (PIMAGE_OPTIONAL_HEADER) &(pImageNtHeaders->OptionalHeader);

	pImageSectionHeader = (PIMAGE_SECTION_HEADER) ((DWORD) pImageNtHeaders + sizeof (IMAGE_NT_HEADERS));
	int	LastPointer = 0;
	int	EndSections;
	int dwCount;
	for (dwCount = 0; dwCount != pImageNtHeaders->FileHeader.NumberOfSections; dwCount++)
	{
		if (pImageSectionHeader->PointerToRawData > LastPointer)
		{
			LastPointer = pImageSectionHeader->PointerToRawData;
			EndSections = LastPointer + pImageSectionHeader->SizeOfRawData;
		}
		PrintImageSectionHeader(pImageSectionHeader);
		pImageSectionHeader = (PIMAGE_SECTION_HEADER) ((DWORD) pImageSectionHeader + sizeof (IMAGE_SECTION_HEADER));
	}

	//pImageSectionHeader = (PIMAGE_SECTION_HEADER) ((DWORD) pImageSectionHeader + sizeof (IMAGE_SECTION_HEADER));

#if 1
	pImageSectionHeader->Name[0] = 'T';
	pImageSectionHeader->Name[1] = 'o';
	pImageSectionHeader->Name[2] = 't';
	pImageSectionHeader->Name[3] = 'o';
	pImageSectionHeader->Name[4] = '\0';

	pImageSectionHeader->Misc.VirtualSize = 512; // ??
	pImageSectionHeader->VirtualAddress = (((EndSections - 1) / pImageOptionalHeader->SectionAlignment) + 1) * pImageOptionalHeader->SectionAlignment;
	pImageSectionHeader->SizeOfRawData = pImageOptionalHeader->FileAlignment;
	pImageSectionHeader->PointerToRawData = pImageSectionHeader->VirtualAddress - pImageOptionalHeader->SizeOfHeaders;
	pImageSectionHeader->PointerToRelocations = 0;
	pImageSectionHeader->PointerToLinenumbers = 0;
	pImageSectionHeader->NumberOfRelocations = 0;
	pImageSectionHeader->NumberOfLinenumbers = 0;
	pImageSectionHeader->Characteristics = IMAGE_SCN_CNT_CODE;// | IMAGE_SCN_CNT_INITIALIZED_DATA;


#elif 0
	pImageSectionHeader = (PIMAGE_SECTION_HEADER) ((DWORD) pImageSectionHeader - sizeof (IMAGE_SECTION_HEADER));

  // CREATE NEW SECTION
  IMAGE_SECTION_HEADER newSectionHeader;
  memcpy(&newSectionHeader, pImageSectionHeader, sizeof(IMAGE_SECTION_HEADER));
  newSectionHeader.PointerToRawData = 3 * 512;
  newSectionHeader.VirtualAddress = 3 * 4096;
  newSectionHeader.Misc.VirtualSize = 8;
  newSectionHeader.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;
  strcpy(newSectionHeader.Name, "Toto");
  memcpy((PIMAGE_SECTION_HEADER) ((DWORD) pImageSectionHeader + sizeof(IMAGE_SECTION_HEADER)), &newSectionHeader, sizeof(IMAGE_SECTION_HEADER));

	pImageSectionHeader = (PIMAGE_SECTION_HEADER) ((DWORD) pImageSectionHeader + sizeof (IMAGE_SECTION_HEADER));
#else
	pImageSectionHeader = (PIMAGE_SECTION_HEADER) ((DWORD) pImageSectionHeader - sizeof (IMAGE_SECTION_HEADER));

  // CREATE NEW SECTION
  IMAGE_SECTION_HEADER newSectionHeader;
  memcpy(&newSectionHeader, pImageSectionHeader, sizeof(IMAGE_SECTION_HEADER));
  newSectionHeader.PointerToRawData = 3 * 512;
  newSectionHeader.VirtualAddress = 3 * 4096;
  newSectionHeader.Misc.VirtualSize = 8;
  newSectionHeader.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;
  strcpy(newSectionHeader.Name, "Toto");
  memcpy((PIMAGE_SECTION_HEADER) ((DWORD) pImageSectionHeader + sizeof(IMAGE_SECTION_HEADER)), &newSectionHeader, sizeof(IMAGE_SECTION_HEADER));

	pImageSectionHeader = (PIMAGE_SECTION_HEADER) ((DWORD) pImageSectionHeader + sizeof (IMAGE_SECTION_HEADER));

	pImageSectionHeader->Name[0] = 'T';
	pImageSectionHeader->Name[1] = 'o';
	pImageSectionHeader->Name[2] = 't';
	pImageSectionHeader->Name[3] = 'o';
	pImageSectionHeader->Name[4] = '\0';

	pImageSectionHeader->Misc.VirtualSize = 512; // ??
	pImageSectionHeader->VirtualAddress = (((EndSections - 1) / pImageOptionalHeader->SectionAlignment) + 1) * pImageOptionalHeader->SectionAlignment;
	pImageSectionHeader->SizeOfRawData = pImageOptionalHeader->FileAlignment;
	pImageSectionHeader->PointerToRawData = pImageSectionHeader->VirtualAddress - pImageOptionalHeader->SizeOfHeaders;
	pImageSectionHeader->PointerToRelocations = 0;
	pImageSectionHeader->PointerToLinenumbers = 0;
	pImageSectionHeader->NumberOfRelocations = 0;
	pImageSectionHeader->NumberOfLinenumbers = 0;
#endif

	PrintImageSectionHeader(pImageSectionHeader);
	(pImageFileHeader->NumberOfSections)++;
	pImageOptionalHeader->SizeOfImage = pImageSectionHeader->VirtualAddress + pImageSectionHeader->Misc.VirtualSize;
	//pImageOptionalHeader->SizeOfCode += pImageSectionHeader->Misc.VirtualSize;
	pImageOptionalHeader->AddressOfEntryPoint = pImageSectionHeader->VirtualAddress;



	printf("LastPosition %ld\n", EndSections);
	printf("FileSize %ld\n", GetFileSize(hFile, NULL));
//	printf("e_magic:		0x%04X (%c%c)\n", pImageDosHeader->e_magic, *uFileMap, *(uFileMap + 1));
	//printf("e_lfanew:	 0x%08X\n", pImageDosHeader->e_lfanew);
	
	UnmapViewOfFile(uFileMap);
	CloseHandle(hMapObject);
	CloseHandle(hFile);
	


	// APPEND OPCODE
	hFile = CreateFile(argv[1], FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if ((DWORD) hFile == -1)
		return (-6);
	
	char buffer[512] = {0x6A, 0x00, 0x68, 0x00, 0x30, 0x40, 0x00, 0x68, 0x09, 0x30,
		0x40, 0x00, 0x6A, 0x00, 0x8E8, 0x07, 0x00, 0x00, 0x00, 0x6A, 0x00, 0xE8, 0x06,
	0x00, 0x00, 0x00, 0xFF, 0x25, 0x08, 0x20, 0x40, 0x00, 0xFF, 0x25, 0x00, 0x20, 0x40, 0x00};
	/* memset(buffer, 0xAA, 512); */
	DWORD written;
	WriteFile(hFile, buffer, sizeof(buffer), &written, NULL);
	printf("Patched: %d\n", written);

	CloseHandle(hFile);

	return (0);
}

