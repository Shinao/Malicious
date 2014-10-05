/**
 ** inject.c
 */

#include <windows.h>
#include <stdio.h>

int			inject(char *name);

int			main(int argc, char **argv) 
{
  if (argc < 2)
    return (-1);

  printf("Exit Code: %d\n", inject(argv[1]));
  return (0);
}

int			inject(char *name)
{
  PIMAGE_DOS_HEADER		pImageDosHeader;
  PIMAGE_NT_HEADERS		pImageNtHeaders;
  PIMAGE_OPTIONAL_HEADER	pImageOptionalHeader;
  PIMAGE_SECTION_HEADER		pImageSectionHeader;
  PIMAGE_FILE_HEADER		pImageFileHeader;
  HANDLE			hFile;
  HANDLE			hMapObject;
  PUCHAR	       		uFileMap;

  if (!(hFile = CreateFile(name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, 0)))
    return (-1);

  if (!(hMapObject = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL)))
    return (-2);

  if (!(uFileMap = MapViewOfFile(hMapObject, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0)))
    return (-3);

  pImageDosHeader = (PIMAGE_DOS_HEADER) uFileMap ;	
  if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    return (-4);

  pImageNtHeaders = (PIMAGE_NT_HEADERS) ((PUCHAR) uFileMap + pImageDosHeader->e_lfanew);
  if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    return (-5);

  pImageFileHeader = (PIMAGE_FILE_HEADER) &(pImageNtHeaders->FileHeader);
  pImageOptionalHeader = (PIMAGE_OPTIONAL_HEADER) &(pImageNtHeaders->OptionalHeader);
  pImageSectionHeader = (PIMAGE_SECTION_HEADER) ((DWORD) pImageNtHeaders + sizeof (IMAGE_NT_HEADERS));

  DWORD		LastSection = 0;
  DWORD		EndSection;
  DWORD		FirstSection = 0;
  int dwCount;
  for (dwCount = 0; dwCount < pImageFileHeader->NumberOfSections; dwCount++)
  {
    if (FirstSection == 0 || pImageSectionHeader->VirtualAddress < FirstSection)
      FirstSection = pImageSectionHeader->VirtualAddress;
    if (pImageSectionHeader->VirtualAddress > LastSection)
    {
      LastSection = pImageSectionHeader->PointerToRawData;
      EndSection = LastSection + pImageSectionHeader->SizeOfRawData;
    }

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
    printf("Characteristics: %ld\n", pImageSectionHeader->Characteristics);
    printf("EndOfSection: %ld\n\n", pImageSectionHeader->PointerToRawData + pImageSectionHeader->SizeOfRawData);

    if (dwCount < pImageFileHeader->NumberOfSections - 1)
      pImageSectionHeader = (PIMAGE_SECTION_HEADER) ((DWORD) pImageSectionHeader + sizeof (IMAGE_SECTION_HEADER));
  }

  printf("Last Section: %ld\n", LastSection);
  printf("Padding Section Header: %ld\n", FirstSection - pImageDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
  printf("LastSectionPosition %ld\n", EndSection);
  printf("Base Image: %lx\n", pImageOptionalHeader->ImageBase);
  printf("Base Code: %ld\n", pImageOptionalHeader->BaseOfCode);
  printf("Entry Point: %ld\n", pImageOptionalHeader->AddressOfEntryPoint);
  printf("Size Image: %ld\n", pImageOptionalHeader->SizeOfImage);
  printf("Size Code: %ld\n", pImageOptionalHeader->SizeOfCode);
  printf("Size Headers: %ld\n", pImageOptionalHeader->SizeOfHeaders);

  return (0);


  // // CREATE NEW SECTION
  // IMAGE_SECTION_HEADER newSectionHeader;
  // memcpy(&newSectionHeader, pImageSectionHeader, sizeof(IMAGE_SECTION_HEADER));
  // newSectionHeader.PointerToRawData = 3 * 512;
  // newSectionHeader.VirtualAddress = 3 * 4096;
  // newSectionHeader.Misc.VirtualSize = 8;
  // newSectionHeader.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;
  // strcpy(newSectionHeader.Name, (char *) "ImIn");
  // memcpy((PIMAGE_SECTION_HEADER) ((DWORD) pImageSectionHeader + sizeof(IMAGE_SECTION_HEADER)), &newSectionHeader, sizeof(IMAGE_SECTION_HEADER));

  // // ADD PROPERTIES
  // pImageFileHeader->NumberOfSections++;
  // pImageOptionalHeader->SizeOfImage = newSectionHeader.VirtualAddress + newSectionHeader.Misc.VirtualSize;
  // pImageOptionalHeader->AddressOfEntryPoint = newSectionHeader.VirtualAddress;


  // UnmapViewOfFile(uFileMap);
  // CloseHandle(hMapObject);
  // CloseHandle(hFile);
  // 

  // // APPEND OPCODE
  // hFile = CreateFile(name, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
  // if ((DWORD) hFile == -1)
  //   return (-6);
  // 
  // char buffer[512] = {0x6A, 0x00, 0x68, 0x00, 0x30, 0x40, 0x00, 0x68, 0x09, 0x30, 
  //   0x40, 0x00, 0x6A, 0x00, 0x8E8, 0x07, 0x00, 0x00, 0x00, 0x6A, 0x00, 0xE8, 0x06,
  // 0x00, 0x00, 0x00, 0xFF, 0x25, 0x08, 0x20, 0x40, 0x00, 0xFF, 0x25, 0x00, 0x20, 0x40, 0x00};
  // /* memset(buffer, 0xAA, 512); */
  // DWORD written;
  // WriteFile(hFile, buffer, sizeof(buffer), &written, NULL);
  // printf("Patched: %d\n", written);
  // CloseHandle(hFile);

  return (0);
}

