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
strcmp:
mov	al, [ecx]
mov	ah, [edx]
cmp	al, ah
jne	nomatch
test	al, al
jz	match
test	ah, ah
jz	match
inc	ecx
inc	edx
jmp	strcmp
match:
xor	eax, eax
nomatch:
ret
