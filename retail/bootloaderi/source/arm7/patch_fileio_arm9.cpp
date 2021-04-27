#include "patch_fileio_arm9.h"
#include <stdio.h>
#include <string.h>

#define MINMATCH_IOCTRL   8

static uint8_t bitSum(uint64_t value)
{
  uint8_t tmp = 0 ;
  for (int i=0;i<sizeof(value)*8;i++)
  {
    if (value & (1ull << i))
      tmp++ ;
  }
  return tmp ;
}

static uint32_t fio_addresses[0x80] ;
static uint64_t fio_masks[0x80] ;
static uint8_t fio_suspectCount ;

void patchFileIO_addSuspect(uint32_t address, uint8_t ioCtrlCode)
{
  if (ioCtrlCode >= 0x40)
    return ;
  for (uint8_t i=0;i<fio_suspectCount;i++)
  {
    if (fio_addresses[i] == address)
    {
      fio_masks[i] |= (1ull << ioCtrlCode) ;
    }
  }
  if (fio_suspectCount + 1 < 0x80)
  {
    fio_addresses[fio_suspectCount] = address ;
    fio_masks[fio_suspectCount] = 1ull << ioCtrlCode ;
    fio_suspectCount++ ;
  }
}


// TODO:
// The below two function use very similiar code that only differ in the event
// something was found. It could be replaced with an enumerating function that
// is called by these two functions

// In the first search iteration we try to locate the fileIO function.
// we fill a suspect list with the addresses an mask of r1 arguments
// and filter out the first match that reaches the MINMATCH_IOCTRL
uint32_t patchFileIO_findIOCtrlFunction(uint8_t *arm9CodePtr, uint32_t arm9CodeSize) 
{
  fio_suspectCount = 0 ;
  memset(fio_masks, 0, sizeof(fio_masks)) ;
 
  uint16_t *curPtr = (uint16_t *)arm9CodePtr ;
  uint32_t *curPtr32 = (uint32_t *)arm9CodePtr ;
    
    
  // TODO: 
  // The seperate rXIsConst1 are uggly and creates cluttered code
  // so it should replaced by a more general approach for all rX and all 
  // constants that gets loaded via "ldr rX, =???" or "mov rX, #const"
  bool r2IsConst1 = false ;
  bool r4IsConst1 = false ;
  bool r5IsConst1 = false ;
  bool r6IsConst1 = false ;
  bool r7IsConst1 = false ;
  bool r8IsConst1 = false ;
  bool r9IsConst1 = false ;
  uint8_t r1LastConst8Bit = 0xff ;
  uint32_t lastFunctionentry = 0 ;
  uint32_t branchProxy = 0 ;
  uint32_t arm9Base = (uint32_t)arm9CodePtr, arm9Size = arm9CodeSize, arm9ROMOffset=(uint32_t)arm9CodePtr ;
 
  for (uint32_t pos = arm9ROMOffset/2;pos<(arm9ROMOffset+arm9Size)/2;pos++)
  {
    if ((curPtr[pos] & 0xFF00) == 0xb500)
    {
      // thumb code for push {[...], lr}
      // we assume all fileIO to have this as the first instruction for frame
      // keeping
      lastFunctionentry = pos * 2 ;
    } else
/*
    if ()
    {
      // using a branch proxy? For thumb that is usually in r3
      // so cache ldr r3, =??? into the jump proxy
      // TODO
    } else 
*/
    if ((curPtr[pos] & 0xFF00) == 0x2100)
    {
      // thumb code for mov r1, #const8Bit
      r1LastConst8Bit = curPtr[pos] & 0x00FF ;
    } else
    if ((curPtr[pos] & 0xFF00) == 0x2200)
    {
      // thumb code for mov r2, #const8Bit
      r2IsConst1 = ((curPtr[pos] & 0x00FF) == 1) ;
    } else
    if ((curPtr[pos] & 0xFFFF) == 0x1c0a)
    {
      // thumb code for add r2, r1, #0
      // so copy the r2 value to r1, used in some WriteFile binaries
      r2IsConst1 = (r1LastConst8Bit == 1) ;
    } else
    if (((curPtr[pos] & 0xF000) <= 0x8000)  && ((curPtr[pos] & 0x000F) == 0x0001))
    {
      // any other operation with r1 as rd invalidates r1
      r1LastConst8Bit = 0xff ;
    }

    // we should invalidate r1 and r2 constants, if we have any over operation 
    // on r1/r2 but for now we just live with false positives
    // there are still pop operations and ldr's for r1

    // we invalidate r1 and r2 as soon as any call was detected
    // but if the pattern matches, we will save that location for further
    // analysis
    // There is another call via BX ioctrl(i.e. used for the CloseFile)
    // But that BX uses the address when loaded not the file offset
    // so we do not yet parse that until we check for the arm9(i) addresses
    // and traslate them -> TODO
    if ((curPtr[pos] & 0xF000) == 0xf000)
    {
      if (r2IsConst1 && (r1LastConst8Bit != 0xff))
      {
        uint32_t callTarget = 0;
        // extract the 23 Bit constant
        callTarget |= ((uint32_t)(curPtr[pos] & 0x07FF)) << 12 ;
        callTarget |= ((uint32_t)(curPtr[pos+1] & 0x07FF)) << 1 ;
        // Sign extension to 32 bit
        if (callTarget & 0xFFC00000)
          callTarget |= 0xFFC00000 ;
        // Then add it to the current prefetch address PC+4
        callTarget = (pos*2) + 4 + callTarget ;
        // and do the Buffer -> VMA Translation
        callTarget = 1 + callTarget + arm9Base - arm9ROMOffset ;
        // and remember!
        patchFileIO_addSuspect(callTarget, r1LastConst8Bit) ;
      } 
      r2IsConst1 = false ;
      r1LastConst8Bit = 0xff ;
    }
  }

  for (uint32_t pos = arm9ROMOffset/4;pos<(arm9ROMOffset+arm9Size)/4;pos++)
  {
    if ((curPtr32[pos] & 0xFFFF4000) == 0xe92d4000)
    {
      // arm32 code for stm sp!, {[...], lr}
      // we assume all fileIO to have this as the first instruction for frame
      // keeping, except if the previous one was a push too
      if ((curPtr32[pos-1] & 0xFFFF0000) == 0xe92d0000)
      {
        lastFunctionentry = (pos-1) * 4 ;
      } else
      {
        lastFunctionentry = pos * 4 ;
      }
    } else
    if ((curPtr32[pos] & 0xFFFF8000) == 0xe8bd8000)
    {
      // arm32 code for ldmia sp!, {[...], pc}
      // we assume all fileIO to have this as the last instruction for frame
      // keeping
      // a new funcion is likely to start next (or possibly 
      // consts of the one before) we assume that the previous function ended 
      // here if we got a function without pushes
      lastFunctionentry = (pos+1) * 4 ;
    } else
    if ((curPtr32[pos] & 0xFFFFFF00) == 0xe59fc000)
    {
      // using a branch proxy? For thumb that is usually in r12
      // so cache ldr r12, =??? into the jump proxy
      branchProxy = curPtr32[pos + 2 + (curPtr32[pos] & 0xFF) / 4] ;  
    } else
    if ((curPtr32[pos] & 0xFFFFFF00) == 0xe3a01000)
    {
      // arm32 code for mov r1, #const8Bit
      r1LastConst8Bit = curPtr32[pos] & 0x00FF ;
    } else
    if ((curPtr32[pos] & 0xFFFFFF00) == 0xe3a02000)
    {
      // arm32 code for mov r2, #const8Bit
      r2IsConst1 = ((curPtr32[pos] & 0x00FF) == 1) ;
    } else
    if ((curPtr32[pos] & 0xFFFFFF00) == 0xe3a07000)
    {
      // arm32 code for mov r7, #const8Bit
      r7IsConst1 = ((curPtr32[pos] & 0x00FF) == 1) ;
    } else
    if ((curPtr32[pos] & 0xFFFFFF00) == 0xe3a04000)
    {
      // arm32 code for mov r4, #const8Bit
      r4IsConst1 = ((curPtr32[pos] & 0x00FF) == 1) ;
    } else
    if ((curPtr32[pos] & 0xFFFFFF00) == 0xe3a05000)
    {
      // arm32 code for mov r5, #const8Bit
      r5IsConst1 = ((curPtr32[pos] & 0x00FF) == 1) ;
    } else
    if ((curPtr32[pos] & 0xFFFFFF00) == 0xe3a06000)
    {
      // arm32 code for mov r6, #const8Bit
      r6IsConst1 = ((curPtr32[pos] & 0x00FF) == 1) ;
    } else
    if ((curPtr32[pos] & 0xFFFFFF00) == 0xe3a08000)
    {
      // arm32 code for mov r8, #const8Bit
      r8IsConst1 = ((curPtr32[pos] & 0x00FF) == 1) ;
    } else
    if ((curPtr32[pos] & 0xFFFFFF00) == 0xe3a09000)
    {
      // arm32 code for mov r8, #const8Bit
      r9IsConst1 = ((curPtr32[pos] & 0x00FF) == 1) ;
    } else
    if (curPtr32[pos] == 0xe1a02004)
    {
      // cpy r2, r4
      r2IsConst1 = r4IsConst1 ;
    } else
    if (curPtr32[pos] == 0xe1a02005)
    {
      // cpy r2, r5
      r2IsConst1 = r5IsConst1 ;
    } else
    if (curPtr32[pos] == 0xe1a02006)
    {
      // cpy r2, r6
      r2IsConst1 = r6IsConst1 ;
    } else
    if (curPtr32[pos] == 0xe1a02007)
    {
      // cpy r2, r7
      r2IsConst1 = r7IsConst1 ;
    } else
    if (curPtr32[pos] == 0xe1a02008)
    {
      // cpy r2, r8
      r2IsConst1 = r8IsConst1 ;
    } else
    if (curPtr32[pos] == 0xe1a02009)
    {
      // cpy r2, r9
      r2IsConst1 = r9IsConst1 ;
    } else
    if (curPtr32[pos] == 0xe1a01004)
    {
      // cpy r1, r4
      if (r4IsConst1)
        r1LastConst8Bit = 1 ;
    } else
    if (curPtr32[pos] == 0xe1a01005)
    {
      // cpy r1, r5
      if (r5IsConst1)
        r1LastConst8Bit = 1 ;
    } else
    if (curPtr32[pos] == 0xe1a01006)
    {
      // cpy r1, r6
      if (r6IsConst1)
        r1LastConst8Bit = 1 ;
    } else
    if (curPtr32[pos] == 0xe1a01007)
    {
      // cpy r1, r7
      if (r7IsConst1)
        r1LastConst8Bit = 1 ;
    } else
    if (curPtr32[pos] == 0xe1a01008)
    {
      // cpy r1, r8
      if (r8IsConst1)
        r1LastConst8Bit = 1 ;
    } else
    if (curPtr32[pos] == 0xe1a01009)
    {
      // cpy r1, r9
      if (r9IsConst1)
        r1LastConst8Bit = 1 ;
    }
    // we should invalidate r1 and r2 constants, if we have any over operation 
    // on r1/r2 but for now we just live with false positives
    // there are still pop operations and ldr's for r1

    // we invalidate r1 and r2 as soon as any call was detected
    // but if the pattern matches, we will save that location for further
    // analysis
    // There is another call via BX ioctrl(i.e. used for the CloseFile)
    // But that BX uses the address when loaded not the file offset
    // so we do not yet parse that until we check for the arm9(i) addresses
    // and traslate them -> TODO
    if ((curPtr32[pos] & 0xFF000000) == 0xeb000000)
    {
      if (r2IsConst1 && (r1LastConst8Bit != 0xff))
      {
        uint32_t callTarget = 0;
        // extract the 23 Bit constant
        callTarget = ((uint32_t)(curPtr32[pos] & 0x00FFFFFF)) << 2 ;
        // Sign extension to 32 bit
        if (callTarget & 0xFE000000)
          callTarget |= 0xFE000000 ;
        // Then add it to the current prefetch address PC+4
        callTarget = (pos*4) + 8 + callTarget ;
        // and do the Buffer -> VMA Translation
        callTarget = callTarget + arm9Base - arm9ROMOffset;
        // and remember!
        patchFileIO_addSuspect(callTarget, r1LastConst8Bit) ;
      } 
      r2IsConst1 = false ;
      r4IsConst1 = false ;
      r5IsConst1 = false ;
      r6IsConst1 = false ;
      r7IsConst1 = false ;
      r8IsConst1 = false ;
      r9IsConst1 = false ;
      r1LastConst8Bit = 0xff ;
    } else if (curPtr32[pos] == 0xe12fff1c)
    {
      // BX r12 (used saved branch proxy)
      if (r2IsConst1 && (r1LastConst8Bit != 0xff))
      {
        uint32_t callTarget = branchProxy ;
        // and remember!
        patchFileIO_addSuspect(callTarget, r1LastConst8Bit) ;
      } 
      r2IsConst1 = false ;
      r4IsConst1 = false ;
      r5IsConst1 = false ;
      r6IsConst1 = false ;
      r7IsConst1 = false ;
      r8IsConst1 = false ;
      r9IsConst1 = false ;
      r1LastConst8Bit = 0xff ;
    }
  }  
  
  for (uint8_t i=0;i<fio_suspectCount;i++)
  {
    if (bitSum(fio_masks[i]) >= MINMATCH_IOCTRL)
    {
      return fio_addresses[i] ;
    }
  }
  // we did not find a minmatch
  return 0 ;
}

// in the second search iteration we only remember the entries that call to our
// located ioCtrl match
void patchFileIO_findIOCtrlCallers(SFILEIOLOCATIONS *fileIOLocations, uint8_t *arm9CodePtr, uint32_t arm9CodeSize) 
{
  uint16_t *curPtr = (uint16_t *)arm9CodePtr ;
  uint32_t *curPtr32 = (uint32_t *)arm9CodePtr ;
    
  // TODO: 
  // The seperate rXIsConst1 are uggly and creates cluttered code
  // so it should replaced by a more general approach for all rX and all 
  // constants that gets loaded via "ldr rX, =???" or "mov rX, #const"
  bool r2IsConst1 = false ;
  bool r4IsConst1 = false ;
  bool r5IsConst1 = false ;
  bool r6IsConst1 = false ;
  bool r7IsConst1 = false ;
  bool r8IsConst1 = false ;
  bool r9IsConst1 = false ;
  uint8_t r1LastConst8Bit = 0xff ;
  uint32_t lastFunctionentry = 0 ;
  uint32_t branchProxy = 0 ;
  uint32_t arm9Base = (uint32_t)arm9CodePtr, arm9Size = arm9CodeSize, arm9ROMOffset=(uint32_t)arm9CodePtr ;
 
  for (uint32_t pos = arm9ROMOffset/2;pos<(arm9ROMOffset+arm9Size)/2;pos++)
  {
    if ((curPtr[pos] & 0xFF00) == 0xb500)
    {
      // thumb code for push {[...], lr}
      // we assume all fileIO to have this as the first instruction for frame
      // keeping
      lastFunctionentry = pos * 2 ;
    } else
/*
    if ()
    {
      // using a branch proxy? For thumb that is usually in r3
      // so cache ldr r3, =??? into the jump proxy
      // TODO
    } else 
*/
    if ((curPtr[pos] & 0xFF00) == 0x2100)
    {
      // thumb code for mov r1, #const8Bit
      r1LastConst8Bit = curPtr[pos] & 0x00FF ;
    } else
    if ((curPtr[pos] & 0xFF00) == 0x2200)
    {
      // thumb code for mov r2, #const8Bit
      r2IsConst1 = ((curPtr[pos] & 0x00FF) == 1) ;
    } else
    if ((curPtr[pos] & 0xFFFF) == 0x1c0a)
    {
      // thumb code for add r2, r1, #0
      // so copy the r2 value to r1, used in some WriteFile binaries
      r2IsConst1 = (r1LastConst8Bit == 1) ;
    } else
    if (((curPtr[pos] & 0xF000) <= 0x8000)  && ((curPtr[pos] & 0x000F) == 0x0001))
    {
      // any other operation with r1 as rd invalidates r1
      r1LastConst8Bit = 0xff ;
    }

    // we should invalidate r1 and r2 constants, if we have any over operation 
    // on r1/r2 but for now we just live with false positives
    // there are still pop operations and ldr's for r1

    // we invalidate r1 and r2 as soon as any call was detected
    // but if the pattern matches, we will save that location for further
    // analysis
    // There is another call via BX ioctrl(i.e. used for the CloseFile)
    // But that BX uses the address when loaded not the file offset
    // so we do not yet parse that until we check for the arm9(i) addresses
    // and traslate them -> TODO
    if ((curPtr[pos] & 0xF000) == 0xf000)
    {
      if (r2IsConst1 && (r1LastConst8Bit != 0xff))
      {
        uint32_t callTarget = 0;
        // extract the 23 Bit constant
        callTarget |= ((uint32_t)(curPtr[pos] & 0x07FF)) << 12 ;
        callTarget |= ((uint32_t)(curPtr[pos+1] & 0x07FF)) << 1 ;
        // Sign extension to 32 bit
        if (callTarget & 0xFFC00000)
          callTarget |= 0xFFC00000 ;
        // Then add it to the current prefetch address PC+4
        callTarget = (pos*2) + 4 + callTarget ;
        // and do the Buffer -> VMA Translation
        callTarget = 1 + callTarget + arm9Base - arm9ROMOffset ;
        // if this is the correct call Target, remember the caller
        if ((uint32_t)fileIOLocations->ioCtrl == callTarget)
        {
          if (r1LastConst8Bit < 0x40)
          {
            fileIOLocations->ioFunctions[r1LastConst8Bit] = (FILEIO_FUNCTION)(1 + lastFunctionentry + arm9Base - arm9ROMOffset) ;
          }
        }
      } 
      r2IsConst1 = false ;
      r1LastConst8Bit = 0xff ;
    }
  }

  for (uint32_t pos = arm9ROMOffset/4;pos<(arm9ROMOffset+arm9Size)/4;pos++)
  {
    if ((curPtr32[pos] & 0xFFFF4000) == 0xe92d4000)
    {
      // arm32 code for stm sp!, {[...], lr}
      // we assume all fileIO to have this as the first instruction for frame
      // keeping, except if the previous one was a push too
      if ((curPtr32[pos-1] & 0xFFFF0000) == 0xe92d0000)
      {
        lastFunctionentry = (pos-1) * 4 ;
      } else
      {
        lastFunctionentry = pos * 4 ;
      }
    } else
    if ((curPtr32[pos] & 0xFFFF8000) == 0xe8bd8000)
    {
      // arm32 code for ldmia sp!, {[...], pc}
      // we assume all fileIO to have this as the last instruction for frame
      // keeping
      // a new funcion is likely to start next (or possibly 
      // consts of the one before) we assume that the previous function ended 
      // here if we got a function without pushes
      lastFunctionentry = (pos+1) * 4 ;
    } else
    if ((curPtr32[pos] & 0xFFFFFF00) == 0xe59fc000)
    {
      // using a branch proxy? For thumb that is usually in r12
      // so cache ldr r12, =??? into the jump proxy
      branchProxy = curPtr32[pos + 2 + (curPtr32[pos] & 0xFF) / 4] ;  
    } else
    if ((curPtr32[pos] & 0xFFFFFF00) == 0xe3a01000)
    {
      // arm32 code for mov r1, #const8Bit
      r1LastConst8Bit = curPtr32[pos] & 0x00FF ;
    } else
    if ((curPtr32[pos] & 0xFFFFFF00) == 0xe3a02000)
    {
      // arm32 code for mov r2, #const8Bit
      r2IsConst1 = ((curPtr32[pos] & 0x00FF) == 1) ;
    } else
    if ((curPtr32[pos] & 0xFFFFFF00) == 0xe3a07000)
    {
      // arm32 code for mov r7, #const8Bit
      r7IsConst1 = ((curPtr32[pos] & 0x00FF) == 1) ;
    } else
    if ((curPtr32[pos] & 0xFFFFFF00) == 0xe3a04000)
    {
      // arm32 code for mov r4, #const8Bit
      r4IsConst1 = ((curPtr32[pos] & 0x00FF) == 1) ;
    } else
    if ((curPtr32[pos] & 0xFFFFFF00) == 0xe3a05000)
    {
      // arm32 code for mov r5, #const8Bit
      r5IsConst1 = ((curPtr32[pos] & 0x00FF) == 1) ;
    } else
    if ((curPtr32[pos] & 0xFFFFFF00) == 0xe3a06000)
    {
      // arm32 code for mov r6, #const8Bit
      r6IsConst1 = ((curPtr32[pos] & 0x00FF) == 1) ;
    } else
    if ((curPtr32[pos] & 0xFFFFFF00) == 0xe3a08000)
    {
      // arm32 code for mov r8, #const8Bit
      r8IsConst1 = ((curPtr32[pos] & 0x00FF) == 1) ;
    } else
    if ((curPtr32[pos] & 0xFFFFFF00) == 0xe3a09000)
    {
      // arm32 code for mov r8, #const8Bit
      r9IsConst1 = ((curPtr32[pos] & 0x00FF) == 1) ;
    } else
    if (curPtr32[pos] == 0xe1a02004)
    {
      // cpy r2, r4
      r2IsConst1 = r4IsConst1 ;
    } else
    if (curPtr32[pos] == 0xe1a02005)
    {
      // cpy r2, r5
      r2IsConst1 = r5IsConst1 ;
    } else
    if (curPtr32[pos] == 0xe1a02006)
    {
      // cpy r2, r6
      r2IsConst1 = r6IsConst1 ;
    } else
    if (curPtr32[pos] == 0xe1a02007)
    {
      // cpy r2, r7
      r2IsConst1 = r7IsConst1 ;
    } else
    if (curPtr32[pos] == 0xe1a02008)
    {
      // cpy r2, r8
      r2IsConst1 = r8IsConst1 ;
    } else
    if (curPtr32[pos] == 0xe1a02009)
    {
      // cpy r2, r9
      r2IsConst1 = r9IsConst1 ;
    } else
    if (curPtr32[pos] == 0xe1a01004)
    {
      // cpy r1, r4
      if (r4IsConst1)
        r1LastConst8Bit = 1 ;
    } else
    if (curPtr32[pos] == 0xe1a01005)
    {
      // cpy r1, r5
      if (r5IsConst1)
        r1LastConst8Bit = 1 ;
    } else
    if (curPtr32[pos] == 0xe1a01006)
    {
      // cpy r1, r6
      if (r6IsConst1)
        r1LastConst8Bit = 1 ;
    } else
    if (curPtr32[pos] == 0xe1a01007)
    {
      // cpy r1, r7
      if (r7IsConst1)
        r1LastConst8Bit = 1 ;
    } else
    if (curPtr32[pos] == 0xe1a01008)
    {
      // cpy r1, r8
      if (r8IsConst1)
        r1LastConst8Bit = 1 ;
    } else
    if (curPtr32[pos] == 0xe1a01009)
    {
      // cpy r1, r9
      if (r9IsConst1)
        r1LastConst8Bit = 1 ;
    }
    // we should invalidate r1 and r2 constants, if we have any over operation 
    // on r1/r2 but for now we just live with false positives
    // there are still pop operations and ldr's for r1

    // we invalidate r1 and r2 as soon as any call was detected
    // but if the pattern matches, we will save that location for further
    // analysis
    // There is another call via BX ioctrl(i.e. used for the CloseFile)
    // But that BX uses the address when loaded not the file offset
    // so we do not yet parse that until we check for the arm9(i) addresses
    // and traslate them -> TODO
    if ((curPtr32[pos] & 0xFF000000) == 0xeb000000)
    {
      if (r2IsConst1 && (r1LastConst8Bit != 0xff))
      {
        uint32_t callTarget = 0;
        // extract the 23 Bit constant
        callTarget = ((uint32_t)(curPtr32[pos] & 0x00FFFFFF)) << 2 ;
        // Sign extension to 32 bit
        if (callTarget & 0xFE000000)
          callTarget |= 0xFE000000 ;
        // Then add it to the current prefetch address PC+4
        callTarget = (pos*4) + 8 + callTarget ;
        // and do the Buffer -> VMA Translation
        callTarget = callTarget + arm9Base - arm9ROMOffset;
        // if this is the correct call Target, remember the caller
        if ((uint32_t)fileIOLocations->ioCtrl == callTarget)
        {
          if (r1LastConst8Bit < 0x40)
          {
            fileIOLocations->ioFunctions[r1LastConst8Bit]  = (FILEIO_FUNCTION)(lastFunctionentry + arm9Base - arm9ROMOffset) ;
          }
        }

      } 
      r2IsConst1 = false ;
      r4IsConst1 = false ;
      r5IsConst1 = false ;
      r6IsConst1 = false ;
      r7IsConst1 = false ;
      r8IsConst1 = false ;
      r9IsConst1 = false ;
      r1LastConst8Bit = 0xff ;
    } else if (curPtr32[pos] == 0xe12fff1c)
    {
      // BX r12 (used saved branch proxy)
      if (r2IsConst1 && (r1LastConst8Bit != 0xff))
      {
        uint32_t callTarget = branchProxy ;
        // if this is the correct call Target, remember the caller
        if ((uint32_t)fileIOLocations->ioCtrl == callTarget)
        {
          if (r1LastConst8Bit < 0x40)
          {
            fileIOLocations->ioFunctions[r1LastConst8Bit]  = (FILEIO_FUNCTION)(lastFunctionentry + arm9Base - arm9ROMOffset) ;
          }
        }
      } 
      r2IsConst1 = false ;
      r4IsConst1 = false ;
      r5IsConst1 = false ;
      r6IsConst1 = false ;
      r7IsConst1 = false ;
      r8IsConst1 = false ;
      r9IsConst1 = false ;
      r1LastConst8Bit = 0xff ;
    }
  }  
}

int patchFileIO_findFileIO(struct SFILEIOLOCATIONS *fileIOLocations, uint8_t *arm9CodePtr, uint32_t arm9CodeSize) 
{

  fileIOLocations->ioCtrl = (FILEIO_CTRLFUNCTION) patchFileIO_findIOCtrlFunction(arm9CodePtr, arm9CodeSize) ;
  if (fileIOLocations->ioCtrl)
  {
    patchFileIO_findIOCtrlCallers(fileIOLocations, arm9CodePtr, arm9CodeSize) ;
    return true ;
  } else
  {
    return false ;
  }
}