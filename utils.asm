; UTILS
; Random number (EAX: Max && Return Value)
random:
push	ecx
push	edx
mov	ecx, eax
pusha
PDELTA	STime
call	[DELTA pGetSystemTime]
popa
xor	eax, eax
mov	ax, word ptr [DELTA STime.Milliseconds]
shl	eax, 16
mov	ax, word ptr [DELTA STime.Second]
xor	edx, edx
div	ecx
mov	eax, edx
pop	edx
pop	ecx
ret

; Compare two strings : ecx/edx (EAX[0]: MATCH)
stricmp:
mov	al, [ecx]
call	toUpper
mov	ah, al
mov	al, [edx]
call	toUpper
cmp	al, ah
jne	nomatch
test	al, al
jz	match
test	ah, ah
jz	match
inc	ecx
inc	edx
jmp	stricmp
match:
xor	eax, eax
nomatch:
ret

; Char to Upper
toUpper:
cmp	al, 97
jl	notLower
cmp	al, 122
jg	notLower
sub	al, 32
notLower:
ret
