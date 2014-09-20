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

	mov	ebx,	eax ;	FROM NOW ON, EBX MUST BE PROTECTED, IT CONTAINS OUR SAINT ufilemap

	; CHECK MAGIC
	cmp	word ptr [ebx], IMAGE_DOS_SIGNATURE
	jne	JumpCheckError


	; CHECK IMAGE_NET_SIGNATURE
	mov	ecx, ebx
	add	ecx, 03Ch
	mov	edx, ebx
	add	edx, dword ptr [ecx] ; C'est quoi cette data ? Je sais qu'il faut pas la perdre
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
	mov	LastSecPos, 0
Loop_SectionHeader:
	push	esi
	mov	esi, eax
	mov	edi, eax

	;if max
	add	esi, 014h
	add	edi, 010h
	mov	esi, dword ptr [esi]
	add	esi, dword ptr [edi]
	cmp	LastSecPos, esi
	jg 	ContinueLoop
	;then
	mov	LastSecPos, esi
	ContinueLoop:
	pop	esi
	add	esi, 028h
	loop	Loop_SectionHeader


	;mov			eax, dword ptr[LastSecPos]
	;call		print_int




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
