; Source of life
; Macro to avoid repetition when pushing offset with delta
PDELTA		macro	Addr
			mov	eax, offset Addr
			add	eax, ebp
			push	eax
		endm
; Macro to avoid repetition when pushing offset value with delta
PVDELTA		macro	Addr
			mov	eax, offset Addr
			add	eax, ebp
			push	[eax]
		endm
; If we change our mind on ebp
DELTA		equ	ebp + offset
; Such wow
GETADDR		macro	Name, Lib, Save
			PDELTA	Name
			push	[DELTA Lib]
			call	[DELTA pGetProcAddress]
			mov	[DELTA Save], eax
		endm

