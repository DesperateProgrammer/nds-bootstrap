// patch_fileio_arm9

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

  typedef int (* FILEIO_CTRLFUNCTION)(void *fileStruct, uint8_t ctrlCode, uint8_t unknown) ;
  typedef int (* FILEIO_FUNCTION)(void *fileStruct) ;

  typedef struct SFILEIOLOCATIONS
  {
    FILEIO_CTRLFUNCTION   ioCtrl ;
    FILEIO_FUNCTION       ioFunctions[0x40] ;
  } SFILEIOLOCATIONS ;

  int patchFileIO_findFileIO(SFILEIOLOCATIONS *fileIOLocations, uint8_t *arm9CodePtr, uint32_t arm9CodeSize) ;

#ifdef __cplusplus
}
#endif