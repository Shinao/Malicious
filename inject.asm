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
	PeSectionNbAdd		dd	?
	LastSecPos		dd	?

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
	mov		PeMapObject, eax

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
	mov	PeFileMap,	eax
	mov	ebx,	eax

	; CHECK MAGIC
	cmp	word ptr [ebx], IMAGE_DOS_SIGNATURE
	jne	JumpCheckError


	; CHECK IMAGE_NET_SIGNATURE
	mov	ecx, ebx
	add	ecx, 03Ch
	mov	edx, ebx
	add	edx, dword ptr [ecx]
	cmp	dword ptr [edx], IMAGE_NT_SIGNATURE
	jne	JumpCheckError

	; GET NUMBER SECTIONS
	mov	eax, edx
	add	eax, 6
	mov	PeSectionNbAdd, eax
	xor	ecx, ecx
	mov	cx, word ptr[eax]

	; LOOP SECTIONS HEADER
	mov	esi, edx
	add	esi, 0F8h
	mov	ebx, esi ; Keep start of Headers
	Loop_SectionHeader:
	; SHOW NAME
	push eax
	mov	eax, esi
	call	DebugMessageBox
	pop eax
	add	esi, 028h
	loop	Loop_SectionHeader

	; CREATE NEW SECTION HEADER
	; COPY FIRST ONE INTO NEW ONE
	xor	ecx, ecx
	mov	edi, PeSectionNbAdd
	mov	cx, word ptr [edi]
	mov	ecx, 020h
	mov	cx, word ptr[eax]
	mov	ecx, 020h
	mov	edi, esi ; Destination bytes
	mov	esi, ebx ; Source bytes
	mov	ebx, edi ; Keep start of new header
	CreateNewHeader:
	lodsb
	stosb
	loop	CreateNewHeader
	; INCREMENT NUMBER OF SECTION
	xor	eax, eax
	mov	edi, PeSectionNbAdd
	mov	ax, word ptr [edi]
	inc	eax
	mov	ecx, PeSectionNbAdd
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
	; Virtual Address
	popa	; Retrieve registers
	add	edi, 04h
	mov	ecx, 4096
	imul	ecx, eax
	mov	[edi], ecx
	mov	ebx, ecx ; Keep VAddress for EntryPoint
	; Size of raw data : Keep the same TODO - Probably change this
	add	edi, 04h
	; Pointer to raw data
	add	edi, 04h
	mov	ecx, 512
	imul	ecx, eax ; TODO Probably not good (need to size up all section because not all are the same size)
	mov	[edi], ecx
	; Characteristics
	add	edi, 014h
	mov	ecx, IMAGE_SCN_MEM_READ
	or	ecx, IMAGE_SCN_MEM_EXECUTE
	or	ecx, IMAGE_SCN_CNT_CODE
	mov	[edi], ecx

	; TODO
	; TODO CHANGE SIZE OF CODE
	mov	eax, offset PeFileMap
	add	eax, 054h
	; CHANGE ENTRY POINT TODO Need to size every section ?
	add	eax, 0Bh
	mov	[eax], ebx
	; CHANGE SIZE OF IMAGE TODO Size every function ?
	add	eax, 028h
	mov	[eax], ebx
	; CLOSE
	push	PeFileMap
	call	UnmapViewOfFile
	push	PeMapObject
	call	CloseHandle
	push	PeFile
	call	CloseHandle

	; CREATE NEW SECTION 




	; EXIT
	push	0
	call 	ExitProcess


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
