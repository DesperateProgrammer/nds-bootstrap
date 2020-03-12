/*-----------------------------------------------------------------

 Copyright (C) 2005  Michael "Chishm" Chisholm

 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License
 as published by the Free Software Foundation; either version 2
 of the License, or (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

 If you use this code, please give due credit and email me about your
 project at chishm@hotmail.com
------------------------------------------------------------------*/

@---------------------------------------------------------------------------------
	.section ".init"
	.global _start
	.global storedFileCluster
	.global initDisc
	.global gameOnFlashcard
	.global saveOnFlashcard
	.global dsiSD
	.global saveFileCluster
	.global gbaFileCluster
	.global romSize
	.global saveSize
	.global wideCheatFileCluster
	.global wideCheatSize
	.global apPatchFileCluster
	.global apPatchSize
	.global cheatFileCluster
	.global cheatSize
	.global patchOffsetCacheFileCluster
	.global armBinsCluster
	.global cacheFatTable
	.global fatTableFileCluster
	.global ramDumpCluster
	.global srParamsFileCluster
	.global language
	.global dsiMode
	.global donorSdkVer
	.global patchMpuRegion
	.global patchMpuSize
	.global ceCached
	.global consoleModel
	.global romRead_LED
	.global dmaRomRead_LED
	.global boostVram
	.global soundFreq
	.global forceSleepPatch
	.global volumeFix
	.global preciseVolumeControl
	.global logging
@---------------------------------------------------------------------------------
	.align	4
	.arm
@---------------------------------------------------------------------------------
_start:
@---------------------------------------------------------------------------------
	b	startUp

storedFileCluster:
	.word	0x0FFFFFFF		@ default BOOT.NDS
initDisc:
	.word	0x00000001		@ init the disc by default
gameOnFlashcard:
	.word	0x00000000
saveOnFlashcard:
	.word	0x00000000
dldiOffset:
	.word	0x00000000
dsiSD:
	.word	0
saveFileCluster:
	.word	0x00000000		@ .sav file
gbaFileCluster:
	.word	0x00000000		@ .gba file
romSize:
	.word	0x00000000		@ .nds file size
saveSize:
	.word	0x00000000		@ .sav file size
wideCheatFileCluster:
	.word	0x00000000
wideCheatSize:
	.word	0x00000000
apPatchFileCluster:
	.word	0x00000000
apPatchSize:
	.word	0x00000000
cheatFileCluster:
	.word	0x00000000
cheatSize:
	.word	0x00000000
patchOffsetCacheFileCluster:
	.word	0x00000000
armBinsCluster:
	.word	0x00000000
cacheFatTable:
	.word	0x00000000
fatTableFileCluster:
	.word	0x00000000
ramDumpCluster:
	.word	0x00000000
srParamsFileCluster:
	.word	0x00000000
language:
	.word	0x00000000
dsiMode:
	.word	0x00000000
donorSdkVer:
	.word	0x00000000		@ donor SDK version
patchMpuRegion:
	.word	0x00000000
patchMpuSize:
	.word	0x00000000
ceCached:
	.word	0x00000000
consoleModel:
	.word	0x00000000
romRead_LED:
	.word	0x00000000
dmaRomRead_LED:
	.word	0x00000000
boostVram:
	.word	0x00000000
soundFreq:
	.word	0x00000000
forceSleepPatch:
	.word	0x00000000
volumeFix:
	.word	0x00000000
preciseVolumeControl:
	.word	0x00000000
logging:
	.word	0x00000000

startUp:
	mov	r0, #0x04000000
	mov	r1, #0
	str	r1, [r0,#0x208]		@ REG_IME
	str	r1, [r0,#0x210]		@ REG_IE
	str	r1, [r0,#0x218]		@ REG_AUXIE

	mov	r0, #0x12		@ Switch to IRQ Mode
	msr	cpsr, r0
	ldr	sp, =__sp_irq		@ Set IRQ stack

	mov	r0, #0x13		@ Switch to SVC Mode
	msr	cpsr, r0
	ldr	sp, =__sp_svc		@ Set SVC stack

	mov	r0, #0x1F		@ Switch to System Mode
	msr	cpsr, r0
	ldr	sp, =__sp_usr		@ Set user stack

	ldr	r0, =__bss_start	@ Clear BSS section to 0x00
	ldr	r1, =__bss_end
	sub	r1, r1, r0
	bl	ClearMem

@ Load ARM9 region into main RAM
	ldr	r1, =__arm9_source_start
	ldr	r2, =__arm9_start	
	ldr	r3, =__arm9_source_end
	sub	r3, r3, r1
	bl	CopyMem

@ Start ARM9 binary
	ldr	r0, =0x02FFFE24	
	ldr	r1, =_arm9_start
	str	r1, [r0]

	ldr	r3, =arm7_main
	bl	_blx_r3_stub		@ jump to user code

	@ If the user ever returns, restart
	b	_start

@---------------------------------------------------------------------------------
_blx_r3_stub:
@---------------------------------------------------------------------------------
	bx	r3

@---------------------------------------------------------------------------------
@ Clear memory to 0x00 if length != 0
@  r0 = Start Address
@  r1 = Length
@---------------------------------------------------------------------------------
ClearMem:
@---------------------------------------------------------------------------------
	mov	r2, #3			@ Round down to nearest word boundary
	add	r1, r1, r2		@ Shouldnt be needed
	bics	r1, r1, r2		@ Clear 2 LSB (and set Z)
	bxeq	lr			@ Quit if copy size is 0

	mov	r2, #0
ClrLoop:
	stmia	r0!, {r2}
	subs	r1, r1, #4
	bne	ClrLoop
	bx	lr

@---------------------------------------------------------------------------------
@ Copy memory if length	!= 0
@  r1 = Source Address
@  r2 = Dest Address
@  r4 = Dest Address + Length
@---------------------------------------------------------------------------------
CopyMemCheck:
@---------------------------------------------------------------------------------
	sub	r3, r4, r2		@ Is there any data to copy?
@---------------------------------------------------------------------------------
@ Copy memory
@  r1 = Source Address
@  r2 = Dest Address
@  r3 = Length
@---------------------------------------------------------------------------------
CopyMem:
@---------------------------------------------------------------------------------
	mov	r0, #3			@ These commands are used in cases where
	add	r3, r3, r0		@ the length is not a multiple of 4,
	bics	r3, r3, r0		@ even though it should be.
	bxeq	lr			@ Length is zero, so exit
CIDLoop:
	ldmia	r1!, {r0}
	stmia	r2!, {r0}
	subs	r3, r3, #4
	bne	CIDLoop
	bx	lr

@---------------------------------------------------------------------------------
	.align
	.pool
	.end
@---------------------------------------------------------------------------------
