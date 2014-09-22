; inject.asm

.386
.model flat, stdcall
assume fs:nothing

option casemap:none

include		\masm32\include\windows.inc
include		\masm32\include\user32.inc
include		\masm32\include\kernel32.inc

includelib	\masm32\lib\user32.lib
includelib	\masm32\lib\kernel32.lib

include		\masm32\include\msvcrt.inc
includelib	\masm32\lib\msvcrt.lib


.data
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

ErrorMessage	db	"Error",0
FileName	db	"donothing.exe",0
String_string	db	"%s ",0
String_number	db	"%d ",0
NewSectionName	db	"ImIn",0

sGetProcAddress	db	'GetProcAddress', 0 
sMessageBoxA	db	'MessageBoxA', 0 
sLoadLibrary	db	'LoadLibraryA', 0 
sHelloWorld	db	'Hello World (MsgBox Without include lib BIATCH!)', 0
sUser32		db	'USER32.DLL', 0
sKernel32	db	'KERNEL32.DLL', 0
pKernel32	dd	?
pUser32		dd	?
pLoadLibrary	dd	?
pGetProcAddress	dd	?
pMessageBoxA	dd	?



.code

start:

; GETTING KERNEL32 FUNCTIONS
; GET BASE ADDRESS OF KERNEL32
xor 	ebx, ebx
mov 	ebx, fs:[030h] ; PEB
mov 	ebx, [ebx + 0Ch] ; PEB_LDR
mov 	ebx, [ebx + 014h] ; LBR 1st
mov 	ebx, [ebx] ; 2nd entry
mov 	ebx, [ebx] ; 3rd entry : kernel32 module (I hope so)
mov	ebx, [ebx + 010h] ; Base address Kernel32 (Holy grail ?)
mov	pKernel32, ebx

; GET PROPERTIES DLL
mov	esi, [ebx + 03Ch] ; PE Header offset
add	esi, ebx
mov	esi, [esi + 078h] ; Export table offset
add	esi, ebx
mov	edi, [esi + 020h] ; Export Name Table offset
add	edi, ebx
mov	ecx, [esi + 014h] ; Number of functions

; LOOP FROM FUNCTIONS AND GET LoadLibrary & GetProcAddress
xor	eax, eax ; Counter
mov	edx, offset sGetProcAddress ; Search function
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
mov	pGetProcAddress, edx

; Test on LoadLibrary
push	offset sLoadLibrary
push	pKernel32 ; Kernel32
call	pGetProcAddress ; GetProcAddress(kernel32, "LoadLibrary")
mov	pLoadLibrary, eax
push	offset sUser32
call	pLoadLibrary ; LoadLibrary("user32.dll")
mov	pUser32, eax
push	offset sMessageBoxA
push	pUser32 ; User32
call	pGetProcAddress ; GetProcAddress(user32.dll, "MessageBoxA")
mov	pMessageBoxA, eax
push	0
push	offset sHelloWorld
push	offset sHelloWorld
push	0
call	eax

; EXIT TEST
push	0
call 	ExitProcess

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





; OPEN FILE
push	0
push	0
push	OPEN_EXISTING
push	0
push	0
mov	eax,	GENERIC_READ
or	eax,	GENERIC_WRITE
push	eax
push	offset FileName
call	CreateFile
call	CheckError
mov		PeFile,	eax

; CREATE_FILE_MAPPING
push	NULL
push	0
push	0
push	PAGE_READWRITE
push	NULL
push	PeFile
call	CreateFileMapping
call	CheckError
mov	PeMapObject, eax

; MAP_VIEW_OF_FILE
push	0
push	0
push	0
mov	eax,	FILE_MAP_READ
or	eax,	FILE_MAP_WRITE
push	eax
push	PeMapObject
call	MapViewOfFile
call	CheckError
mov	PeFileMap, eax
mov	ebx, eax

; CHECK MAGIC
cmp	word ptr [ebx], IMAGE_DOS_SIGNATURE
jne	JumpCheckError


; CHECK IMAGE_NET_SIGNATURE
mov	ecx, ebx
add	ecx, 03Ch
mov	edx, ebx
add	edx, dword ptr [ecx]
mov	PeNtHeader, edx
cmp	dword ptr [edx], IMAGE_NT_SIGNATURE
jne	JumpCheckError

; GET OPTIONAL HEADER useless so far
mov	PeOptionalHeader, edx
add PeOptionalHeader, 018h

; GET NUMBER SECTIONS
mov	eax, edx
add	eax, 6
mov	PeSectionNb, eax
xor	ecx, ecx
mov	cx, word ptr[eax]

; GET ALIGNMENT
add	eax, 032h
mov	esi, [eax]
mov	SectionAlignment, esi
add	eax, 04h
mov	esi, [eax]
mov	FileAlignment, esi


; LOOP SECTIONS HEADER
mov	esi, edx
add	esi, 0F8h
mov	PeStartHeader, esi
mov	ebx, esi ; Keep start of Headers
mov	LastSec, 0
Loop_SectionHeader:
; GET LAST SECTION
mov	eax, esi
add	eax, 0Ch
cmp	LastSec, eax
jg	keepLastSec
mov	LastSecHeader, esi
mov	LastSec, eax
keepLastSec:
; SHOW NAME
mov	eax, esi
call	DebugMessageBox
add	esi, 028h
loop	Loop_SectionHeader


; CREATE NEW SECTION HEADER
; COPY FIRST ONE INTO NEW ONE
mov	ecx, 020h
mov	edi, esi ; Destination bytes
mov	esi, PeStartHeader ; Source bytes
mov	ebx, edi ; Keep start of new header
CreateNewHeader:
lodsb
stosb
loop	CreateNewHeader

; INCREMENT NUMBER OF SECTION
xor	eax, eax
mov	edi, PeSectionNb
mov	ax, word ptr [edi]
inc	eax
mov	ecx, PeSectionNb
mov	word ptr [ecx], ax

; SET PROPERTIES
; SizeOfRawData aligned on FileAlignement (512)
; PointerToRawData = prev.PointerToRawData + prev.SizeOfRawData
; VirtualSize = actual size of the section
; VirtualAdress = prev.VirtualAdress + prev.VirtualSize aligned on SectionAlignment (4096 (0xFFF)) (je crois?)

; COPY THE NAME
mov	ecx, 08h ; Length of Name
mov	esi, offset NewSectionName ; Source bytes
mov	edi, ebx ; Destination bytes
pusha ; Keep registers
CopySectionName:
lodsb
stosb
loop CopySectionName

; Virtual Size
popa	; Retrieve registers
add	edi, 08h
mov	NewSectionCodeSize, endToInject - toInject ; Size of actual code in new section
mov	ecx, NewSectionCodeSize
mov	[edi], ecx

; Virtual Address (Last section VA + Alignment TODO Check if our code not superior ?)
add	edi, 04h
mov	ecx, LastSecHeader
add	ecx, 08h ; LastSecHeader.VirtualSize
mov	eax, [ecx]
add	ecx, 0Ch ; LastSecHeader.VirtualAdress
mov	ebx, ecx ; Keep VAddress for Raw data
add	eax, [ecx]
;pImageSectionHeader->VirtualAddress = (((EndSections - 1) / SectionAlignment) + 1) * SectionAlignment;
sub eax, 1
call	print_int
div SectionAlignment ; divide eax by SectionAlignement
mov		eax, SectionAlignment
add eax, 1
mul SectionAlignment
;add	eax, SectionAlignment
mov	[edi], eax
mov	esi, eax ; Keep New VA for EntryPoint

; Size of raw data (FileAlignment TODO Check if our code not superior?)
add	edi, 04h
mov	eax, FileAlignment
mov	[edi], eax

; Pointer to raw data (Get last section pointer to raw data + size of raw data)
add	edi, 04h
mov	ecx, ebx
add	ecx, 04h
mov	eax, [ecx]
add	ecx, 04h
add	eax, [ecx]
mov	[edi], eax

; Characteristics
add	edi, 010h
mov	ecx, IMAGE_SCN_MEM_READ
or	ecx, IMAGE_SCN_MEM_EXECUTE
or	ecx, IMAGE_SCN_CNT_CODE
mov	[edi], ecx


; CHANGE PE PROPERTIES
; TODO CHANGE SIZE OF CODE
mov	eax, PeNtHeader
add	eax, 01Ch
; CHANGE ENTRY POINT TODO Need to size every section ?
add	eax, 0Ch
mov	[eax], esi
; CHANGE SIZE OF IMAGE TODO Size every function ?
add	eax, 028h
add	ebx, 08h
add	esi, 01h ; TODO - WTF IS THIS SHIT ? (Size of all virtual size + 1?)
mov	[eax], esi
; CLOSE
push	PeFileMap
call	UnmapViewOfFile
push	PeMapObject
call	CloseHandle
push	PeFile
call	CloseHandle


; CREATE NEW SECTION 
; OPEN FILE
push	0
push	FILE_ATTRIBUTE_NORMAL	
push	OPEN_ALWAYS
push	0
push	FILE_SHARE_READ
push	FILE_APPEND_DATA
push	offset FileName
call	CreateFile
mov	eax, PeFile

; INSERT OPCODE
mov	ecx, 512 ; endToInject - toInject ; Number of bytes
mov	esi, toInject ; Source bytes
push	0
push	0
push	ecx
push	esi
push	PeFile
call	WriteFile

; CLOSE
push	PeFile
call	CloseHandle


; EXIT
push	0
call 	ExitProcess


; TEST LABEL INJECTION
toInject:
push	MB_OK
push	0
push	0
push	0
call	MessageBoxA
push	0
call	ExitProcess
endToInject:


print_str	proc
pusha
push	eax
;push	offset String_string
;call	crt_printf
popa
ret
print_str	endp

print_int	proc
pusha
push	eax
push	offset String_number
call	crt_printf
popa
ret
print_int	endp

CheckError:
cmp		eax, INVALID_HANDLE_VALUE
jne		EndErrorDebug
JumpCheckError:
mov		eax, offset FileName
call	DebugMessageBox
push	eax
push	0
call	ExitProcess
EndErrorDebug:
ret

DebugMessageBox	proc
pusha
push	MB_OK
push	offset ErrorMessage
push	eax
push	0
call	MessageBoxA
popa
ret
DebugMessageBox	endp

end		start
