###################################
# Build fileio stub from assembly #
###################################

ifeq ($(strip $(DEVKITARM)),)
$(error "Please set DEVKITARM in your environment. export DEVKITARM=<path to>devkitARM")
endif

export TARGET	:=	$(shell basename $(CURDIR))
export TOPDIR	:=	$(CURDIR)
export SOURCES := ./

include $(DEVKITARM)/base_rules

SFILES		:=	$(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.s)))
TARGETS   := $(SFILES:.s=.o)
 
# -T tmd.ld  
 
all: fileio.elf
	$(PREFIX)objcopy -v -O binary -j .text fileio.elf fileio.bin 
 
%.o : %.s
	$(PREFIX)gcc -nostartfiles -nostdlib -Wa,--strip-local-absolute -Wa,-alhns -c $< -o $@ > $@.lst
   
fileio.elf: $(TARGETS)
	$(PREFIX)ld -T sram.ld  -o $@ $^

clean:
	rm -f *.elf
	rm -f *.o
	rm -f fileio.bin