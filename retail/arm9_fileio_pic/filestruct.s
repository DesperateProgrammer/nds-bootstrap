@---------------------------------------------------------------------------------
	.align	4
	.arm
	.global createFileStruct
@---------------------------------------------------------------------------------
  
  
# This function initiates the file structure as used in the DSi SDK 
# The structure is used on fileIO functions such as open/read/write
# and occupies 32 byte while describing the opened file
  
createFileStruct:
  MOV r2, #0x0
  STR r2, [r0, #0x00]
  STR r2, [r0, #0x04]
  STR r2, [r0, #0x08]
  MOV r1, #0x2300
  STR r1, [r0, #0x0C]
  STR r2, [r0, #0x10]
  STR r2, [r0, #0x14]
  STR r2, [r0, #0x18]
  STR r2, [r0, #0x1C]
  BX lr
