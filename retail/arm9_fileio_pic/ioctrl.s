@---------------------------------------------------------------------------------
	.align	4
	.arm
	.global fileio_ctrl
  .global pFileIOCtrl
@---------------------------------------------------------------------------------

# This code is a trampoline for the ioctrl function in the DSi SDK using 
# executeable. The value of pFileIOCtrl has to be set in order to use the 
# trampoline, otherwise it will return instantly

fileio_ctrl:
  LDR r12, =pFileIOCtrl
  CMP r12, #0
  BXEQ lr
  BXNE r12
  
@ Some magic value to find the location of pFileIOCtrl
@ from outside 
  .word 0xDEADBEEF      @ Header magic
  .hword 0x0004         @ Data Length
  .hword 0x0001         @ Data Descriptor ID and size
  .word 0xCAFEBABE      @ Footer
pFileIOCtrl:
  .word 0x00000000
