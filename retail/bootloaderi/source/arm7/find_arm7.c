#include <stddef.h> // NULL
#include "patch.h"
#include "find.h"
#include "debug_file.h"

//
// Subroutine function signatures ARM7
//

static const u32 relocateStartSignature[1] = {0x027FFFFA};
static const u32 relocateStartSignature5[1]    = {0x3381C0DE}; //  33 81 C0 DE  DE C0 81 33 00 00 00 00 is the marker for the beggining of the relocated area :-)
static const u32 relocateStartSignature5Alt[1] = {0x2106C0DE};

static const u32 nextFunctiontSignature[1] = {0xE92D4000};
static const u32 relocateValidateSignature[1] = {0x400010C};

static const u32 swiHaltSignature1[1] = {0xE59FC004};
static const u32 swiHaltSignature2[1] = {0xE59FC000};
static const u16 swiHaltCmpSignature[1] = {0x2800};
static const u32 swiHaltConstSignature[1] = {0x4000004};
static const u32 swiHaltConstSignatureAlt[1] = {0x4000208};

static const u32 swi12Signature[1] = {0x4770DF12}; // LZ77UnCompReadByCallbackWrite16bit

static const u32 scfgExtSignature[1] = {0x4004008};

static const u16 swiGetPitchTableSignatureThumb[4]    = {0xB570, 0x1C05, 0x2400, 0x4248};
static const u16 swiGetPitchTableSignatureThumbAlt[4] = {0xB570, 0x1C05, 0x4248, 0x2103};
static const u32 swiGetPitchTableSignature1[4]      = {0xE59FC004, 0xE08FC00C, 0xE12FFF1C, 0x00004721};
static const u32 swiGetPitchTableSignature1Alt1[4]  = {0xE59FC004, 0xE08FC00C, 0xE12FFF1C, 0x00004BB9};
static const u32 swiGetPitchTableSignature1Alt2[4]  = {0xE59FC004, 0xE08FC00C, 0xE12FFF1C, 0x00004BC9};
static const u32 swiGetPitchTableSignature1Alt3[4]  = {0xE59FC004, 0xE08FC00C, 0xE12FFF1C, 0x00004BE5};
static const u32 swiGetPitchTableSignature1Alt4[3]  = {0xE59FC000, 0xE12FFF1C, 0x03803BE9};
static const u32 swiGetPitchTableSignature1Alt5[3]  = {0xE59FC000, 0xE12FFF1C, 0x03803E05};
static const u32 swiGetPitchTableSignature1Alt6[3]  = {0xE59FC000, 0xE12FFF1C, 0x03803E09};
static const u32 swiGetPitchTableSignature1Alt7[3]  = {0xE59FC000, 0xE12FFF1C, 0x03803F21};
static const u32 swiGetPitchTableSignature1Alt8[3]  = {0xE59FC000, 0xE12FFF1C, 0x03804189};
static const u32 swiGetPitchTableSignature1Alt9[3]  = {0xE59FC000, 0xE12FFF1C, 0x038049D5};
static const u32 swiGetPitchTableSignature3[3]      = {0xE59FC000, 0xE12FFF1C, 0x03800FD5};
static const u32 swiGetPitchTableSignature3Alt1[3]  = {0xE59FC000, 0xE12FFF1C, 0x03801149};
static const u32 swiGetPitchTableSignature3Alt2[3]  = {0xE59FC000, 0xE12FFF1C, 0x03801215};
static const u32 swiGetPitchTableSignature3Alt3[3]  = {0xE59FC000, 0xE12FFF1C, 0x03804119};
static const u32 swiGetPitchTableSignature3Alt4[3]  = {0xE59FC000, 0xE12FFF1C, 0x03804301};
static const u32 swiGetPitchTableSignature3Alt5[3]  = {0xE59FC000, 0xE12FFF1C, 0x03804305};
static const u32 swiGetPitchTableSignature3Alt6[3]  = {0xE59FC000, 0xE12FFF1C, 0x03804395};
static const u32 swiGetPitchTableSignature3Alt7[3]  = {0xE59FC000, 0xE12FFF1C, 0x03804439};
static const u32 swiGetPitchTableSignature3Alt8[3]  = {0xE59FC000, 0xE12FFF1C, 0x03804559};
static const u32 swiGetPitchTableSignature3Alt9[3]  = {0xE59FC000, 0xE12FFF1C, 0x03804615};
static const u32 swiGetPitchTableSignature3Alt10[3] = {0xE59FC000, 0xE12FFF1C, 0x038053E1};
static const u32 swiGetPitchTableSignature3Alt11[3] = {0xE59FC000, 0xE12FFF1C, 0x038055A5};
static const u32 swiGetPitchTableSignature4[3]      = {0xE59FC000, 0xE12FFF1C, 0x038006A1};
static const u32 swiGetPitchTableSignature4Alt1[3]  = {0xE59FC000, 0xE12FFF1C, 0x03800811};
static const u32 swiGetPitchTableSignature4Alt2[3]  = {0xE59FC000, 0xE12FFF1C, 0x03800919};
static const u32 swiGetPitchTableSignature4Alt3[3]  = {0xE59FC000, 0xE12FFF1C, 0x03800925};
static const u32 swiGetPitchTableSignature4Alt4[3]  = {0xE59FC000, 0xE12FFF1C, 0x038035C5};
static const u32 swiGetPitchTableSignature4Alt5[3]  = {0xE59FC000, 0xE12FFF1C, 0x038035ED};
static const u32 swiGetPitchTableSignature4Alt6[3]  = {0xE59FC000, 0xE12FFF1C, 0x03803715};
static const u32 swiGetPitchTableSignature4Alt7[3]  = {0xE59FC000, 0xE12FFF1C, 0x03803829};
static const u32 swiGetPitchTableSignature4Alt8[3]  = {0xE59FC000, 0xE12FFF1C, 0x03803ED5};
static const u32 swiGetPitchTableSignature4Alt9[3]  = {0xE59FC000, 0xE12FFF1C, 0x03803F15};
static const u32 swiGetPitchTableSignature5[4]      = {0x781A4B06, 0xD3030791, 0xD20106D1, 0x1A404904};

// Sleep patch
static const u32 sleepPatch[2]         = {0x0A000001, 0xE3A00601};
static const u16 sleepPatchThumb[2]    = {0xD002, 0x4831};
static const u16 sleepPatchThumbAlt[2] = {0xD002, 0x0440};

// RAM clear
//static const u32 ramClearSignature[2] = {0x02FFC000, 0x02FFF000};

// Card check pull out
static const u32 cardCheckPullOutSignature1[4] = {0xE92D4000, 0xE24DD004, 0xE59F00B4, 0xE5900000}; // Pokemon Dash, early sdk2
static const u32 cardCheckPullOutSignature2[4] = {0xE92D4018, 0xE24DD004, 0xE59F204C, 0xE1D210B0}; // SDK != 3
static const u32 cardCheckPullOutSignature3[4] = {0xE92D4000, 0xE24DD004, 0xE59F002C, 0xE1D000B0}; // SDK 3

// irq enable
static const u32 irqEnableStartSignature1[4]      = {0xE59FC028, 0xE1DC30B0, 0xE3A01000, 0xE1CC10B0}; // SDK <= 3
static const u32 irqEnableStartSignature4[4]      = {0xE92D4010, 0xE1A04000, 0xEBFFFFF6, 0xE59FC020}; // SDK >= 4
static const u32 irqEnableStartSignature4Alt[4]   = {0xE92D4010, 0xE1A04000, 0xEBFFFFE9, 0xE59FC020}; // SDK 5
static const u16 irqEnableStartSignatureThumb5[5] = {0xB510, 0x1C04, 0xF7FF, 0xFFE4, 0x4B05}; // SDK 5

// SD card reset (SDK 5)
static const u32 sdCardResetSignatureType1[4]      = {0xEBFFFE57, 0xEBFFFF8E, 0xEB000024, 0xE1A05000};
static const u32 sdCardResetSignatureType2[4]      = {0xEBFFFE3D, 0xEBFFFF7E, 0xEB000028, 0xE1A05000};
static const u32 sdCardResetSignatureType3[4]      = {0xEBFFFE4E, 0xEBFFFF89, 0xEB000024, 0xE1A05000};
static const u32 sdCardResetSignatureType4[4]      = {0xEBFFFE48, 0xEBFFFF82, 0xEB000025, 0xE1A05000};
static const u16 sdCardResetSignatureThumbType1[7] = {0xF7FF, 0xFDAB, 0xF7FF, 0xFF5F, 0xF000, 0xF871, 0x1C05};
static const u16 sdCardResetSignatureThumbType2[7] = {0xF7FF, 0xFDBC, 0xF7FF, 0xFF58, 0xF000, 0xF84A, 0x1C05};
static const u16 sdCardResetSignatureThumbType3[7] = {0xF7FF, 0xFD9C, 0xF7FF, 0xFF50, 0xF000, 0xF87A, 0x1C05};
static const u16 sdCardResetSignatureThumbType4[7] = {0xF7FF, 0xFDCE, 0xF7FF, 0xFF68, 0xF000, 0xF85A, 0x1C05};

bool a7GetReloc(const tNDSHeader* ndsHeader, const module_params_t* moduleParams) {
	extern u32 vAddrOfRelocSrc;
	extern u32 relocDestAtSharedMem;

	if (isSdk5(moduleParams)) {
		// Find the relocation signature
		u32 relocationStart = patchOffsetCache.relocateStartOffset;
		if (!patchOffsetCache.relocateStartOffset) {
			relocationStart = (u32)findOffset(
				(u32*)ndsHeader->arm7destination, 0x800,
				relocateStartSignature5, 1
			);
			if (!relocationStart) {
				dbg_printf("Relocation start not found. Trying alt\n");
				relocationStart = (u32)findOffset(
					(u32*)ndsHeader->arm7destination, 0x800,
					relocateStartSignature5Alt, 1
				);
				if (relocationStart>0) relocationStart += 0x28;
			}

			if (relocationStart) {
				patchOffsetCache.relocateStartOffset = relocationStart;
			}
		}
		if (!relocationStart) {
			dbg_printf("Relocation start alt not found\n");
			return false;
		}

		// Validate the relocation signature
		vAddrOfRelocSrc = relocationStart + 0x8;
		// sanity checks
		u32 relocationCheck = patchOffsetCache.relocateValidateOffset;
		if (!patchOffsetCache.relocateValidateOffset) {
			relocationCheck = (u32)findOffset(
				(u32*)ndsHeader->arm7destination, ndsHeader->arm7binarySize,
				relocateValidateSignature, 1
			);
			if (relocationCheck) {
				patchOffsetCache.relocateValidateOffset = relocationCheck;
			}
		}
		u32 relocationCheck2 =
			*(u32*)(relocationCheck - 0x4);

		relocDestAtSharedMem = *(u32*)0x02FFE1A0==0x080037C0 ? 0x37C0000 : 0x37F8000;
		if (relocationCheck + 0xC - vAddrOfRelocSrc + relocDestAtSharedMem > relocationCheck2) {
			dbg_printf("Error in relocation checking\n");
			dbg_hexa(relocationCheck + 0xC - vAddrOfRelocSrc + relocDestAtSharedMem);
			dbg_printf(" ");
			dbg_hexa(relocationCheck2);

			vAddrOfRelocSrc =  relocationCheck + 0xC - relocationCheck2 + relocDestAtSharedMem;
			dbg_printf("vAddrOfRelocSrc\n");
			dbg_hexa(vAddrOfRelocSrc); 
		}

		dbg_printf("Relocation src: ");
		dbg_hexa(vAddrOfRelocSrc);
		dbg_printf("\n");

		return true;
	}

	// Find the relocation signature
    u32 relocationStart = patchOffsetCache.relocateStartOffset;
	if (!patchOffsetCache.relocateStartOffset) {
		relocationStart = (u32)findOffset(
			(u32*)ndsHeader->arm7destination, ndsHeader->arm7binarySize,
			relocateStartSignature, 1
		);

		if (relocationStart) {
			patchOffsetCache.relocateStartOffset = relocationStart;
		}
	}
	if (!relocationStart) {
		dbg_printf("Relocation start not found\n");
		return false;
	}

    // Validate the relocation signature
	u32 forwardedRelocStartAddr = relocationStart + 4;
	while (!*(u32*)forwardedRelocStartAddr || *(u32*)forwardedRelocStartAddr < 0x02000000 || *(u32*)forwardedRelocStartAddr > 0x03000000) {
		forwardedRelocStartAddr += 4;
	}
	vAddrOfRelocSrc = *(u32*)(forwardedRelocStartAddr + 8);
    
    dbg_printf("forwardedRelocStartAddr\n");
    dbg_hexa(forwardedRelocStartAddr);   
    dbg_printf("\nvAddrOfRelocSrc\n");
    dbg_hexa(vAddrOfRelocSrc);
    dbg_printf("\n");  
	
	// Sanity checks
	u32 relocationCheck1 = *(u32*)(forwardedRelocStartAddr + 0xC);
	u32 relocationCheck2 = *(u32*)(forwardedRelocStartAddr + 0x10);
	if (vAddrOfRelocSrc != relocationCheck1 || vAddrOfRelocSrc != relocationCheck2) {
		dbg_printf("Error in relocation checking method 1\n");
		
		// Find the beginning of the next function
		u32 nextFunction = patchOffsetCache.relocateValidateOffset;
		if (!patchOffsetCache.relocateValidateOffset) {
			nextFunction = (u32)findOffset(
				(u32*)relocationStart, ndsHeader->arm7binarySize,
				nextFunctiontSignature, 1
			);
			if (nextFunction) {
				patchOffsetCache.relocateValidateOffset = nextFunction;
			}
		}
	
		// Validate the relocation signature
		forwardedRelocStartAddr = nextFunction - 0x14;
		
		// Validate the relocation signature
		vAddrOfRelocSrc = *(u32*)(nextFunction - 0xC);
		
		// Sanity checks
		relocationCheck1 = *(u32*)(forwardedRelocStartAddr + 0xC);
		relocationCheck2 = *(u32*)(forwardedRelocStartAddr + 0x10);
		if (vAddrOfRelocSrc != relocationCheck1 || vAddrOfRelocSrc != relocationCheck2) {
			dbg_printf("Error in relocation checking method 2\n");
			return false;
		}
	}

	// Get the remaining details regarding relocation
	u32 valueAtRelocStart = *(u32*)forwardedRelocStartAddr;
	relocDestAtSharedMem = *(u32*)valueAtRelocStart;
	if (relocDestAtSharedMem != 0x37F8000) { // Shared memory in RAM
		// Try again
		vAddrOfRelocSrc += *(u32*)(valueAtRelocStart + 4);
		relocDestAtSharedMem = *(u32*)(valueAtRelocStart + 0xC);
		if (relocDestAtSharedMem != 0x37F8000) {
			dbg_printf("Error in finding shared memory relocation area\n");
			return false;
		}
	}

	dbg_printf("Relocation src: ");
	dbg_hexa(vAddrOfRelocSrc);
	dbg_printf("\n");
	dbg_printf("Relocation dst: ");
	dbg_hexa(relocDestAtSharedMem);
	dbg_printf("\n");

	return true;
}

u32* findSwiHaltOffset(const tNDSHeader* ndsHeader, const module_params_t* moduleParams) {
	dbg_printf("findSwiHaltOffset:\n");

	u32* swiHaltOffset = NULL;
	u32 dispStatAddr = (u32)findOffset(
		(u32*)ndsHeader->arm7destination, 0x00001000,//, ndsHeader->arm7binarySize,
		swiHaltConstSignature, 1
	);
	if (!dispStatAddr) {
		dispStatAddr = (u32)findOffset(
			(u32*)ndsHeader->arm7destination, 0x00001000,//, ndsHeader->arm7binarySize,
			swiHaltConstSignatureAlt, 1
		);
	}
	if (dispStatAddr) {
		dispStatAddr += 0x20;
		swiHaltOffset =
			findOffsetBackwards((u32*)dispStatAddr, 0x40,
				(moduleParams->sdk_version > 0x2004000 ? swiHaltSignature2 : swiHaltSignature1), 1
		);
	}
	if (swiHaltOffset) {
		dbg_printf("swiHalt call found\n");
	} else {
		dbg_printf("swiHalt call not found\n");
	}

	dbg_printf("\n");
	return swiHaltOffset;
}

u16* findSwiHaltThumbOffset(const tNDSHeader* ndsHeader, const module_params_t* moduleParams) {
	dbg_printf("findSwiHaltThumbOffset:\n");

	u32 swiHaltOffset = 0;
	if (isSdk5(moduleParams)) {
		extern u32 vAddrOfRelocSrc;

		swiHaltOffset =
			(u32)findOffsetThumb((u16*)vAddrOfRelocSrc, 0x200,
				swiHaltCmpSignature, 1
		);
	}
	if (!swiHaltOffset) {
		u32 dispStatAddr = (u32)findOffset(
			(u32*)ndsHeader->arm7destination, 0x00001000,//, ndsHeader->arm7binarySize,
			swiHaltConstSignature, 1
		);
		if (!dispStatAddr) {
			dispStatAddr = (u32)findOffset(
				(u32*)ndsHeader->arm7destination, 0x00001000,//, ndsHeader->arm7binarySize,
				swiHaltConstSignatureAlt, 1
			);
		}
		if (dispStatAddr) {
			swiHaltOffset =
				(u32)findOffsetBackwardsThumb((u16*)dispStatAddr, 0x40,
					swiHaltCmpSignature, 1
			);
		}
	}
	if (swiHaltOffset) {
		swiHaltOffset -= 8;
		dbg_printf("swiHalt call found\n");
	} else {
		dbg_printf("swiHalt call not found\n");
	}

	dbg_printf("\n");
	return (u16*)swiHaltOffset;
}

u32* a7_findSwi12Offset(const tNDSHeader* ndsHeader) {
	dbg_printf("findSwi12Offset:\n");

	u32* swi12Offset = findOffset(
		(u32*)ndsHeader->arm7destination, 0x00010000,//ndsHeader->arm7binarySize,
		swi12Signature, 1
	);
	if (swi12Offset) {
		dbg_printf("swi 0x12 call found\n");
	} else {
		dbg_printf("swi 0x12 call not found\n");
	}

	dbg_printf("\n");
	return swi12Offset;
}

u32* a7_findScfgExtOffset(const tNDSHeader* ndsHeader) {
	dbg_printf("a7_findScfgExtOffset:\n");

	u32* offset = findOffset(
		(u32*)ndsHeader->arm7destination, 0x00010000,//ndsHeader->arm7binarySize,
		scfgExtSignature, 1
	);
	if (offset) {
		dbg_printf("SCFG_EXT found\n");
	} else {
		dbg_printf("SCFG_EXT call not found\n");
	}

	dbg_printf("\n");
	return offset;
}

u16* findSwiGetPitchTableThumbBranchOffset(const tNDSHeader* ndsHeader) {
	dbg_printf("findSwiGetPitchTableThumbOffset:\n");

	u16* offset = findOffsetThumb(
		(u16*)ndsHeader->arm7destination, ndsHeader->arm7binarySize,
		swiGetPitchTableSignatureThumb, 4
	);
	if (!offset) {
		offset = findOffsetThumb(
			(u16*)ndsHeader->arm7destination, ndsHeader->arm7binarySize,
			swiGetPitchTableSignatureThumbAlt, 4
		);
	}

	if (offset) {
		dbg_printf("swiGetPitchTable thumb branch found\n");
	} else {
		dbg_printf("swiGetPitchTable thumb branch not found\n");
	}

	dbg_printf("\n");
	return offset;
}

u32* findSwiGetPitchTableOffset(const tNDSHeader* ndsHeader, const module_params_t* moduleParams) {
	dbg_printf("findSwiGetPitchTableOffset:\n");

	u32* swiGetPitchTableOffset = NULL;

	if (moduleParams->sdk_version > 0x5000000) {
		swiGetPitchTableOffset = findOffset(
			(u32*)ndsHeader->arm7destination, 0x00010000,//ndsHeader->arm7binarySize,
			swiGetPitchTableSignature5, 4
		);
		if (swiGetPitchTableOffset) {
			dbg_printf("swiGetPitchTable call SDK 5 found\n");
		} else {
			dbg_printf("swiGetPitchTable call SDK 5 not found\n");
		}
	}

	if (!swiGetPitchTableOffset) {
		swiGetPitchTableOffset = findOffset(
			(u32*)ndsHeader->arm7destination, 0x00010000,//ndsHeader->arm7binarySize,
			swiGetPitchTableSignature1, 4
		);
		if (swiGetPitchTableOffset) {
			dbg_printf("swiGetPitchTable SDK <= 2 call found\n");
		} else {
			dbg_printf("swiGetPitchTable SDK <= 2 call not found\n");
		}
	}

	if (!swiGetPitchTableOffset) {
		swiGetPitchTableOffset = findOffset(
			(u32*)ndsHeader->arm7destination, 0x00010000,//ndsHeader->arm7binarySize,
			swiGetPitchTableSignature1Alt1, 4
		);
		if (swiGetPitchTableOffset) {
			dbg_printf("swiGetPitchTable SDK <= 2 call alt 1 found\n");
		} else {
			dbg_printf("swiGetPitchTable SDK <= 2 call alt 1 not found\n");
		}
	}
	if (!swiGetPitchTableOffset) {
		swiGetPitchTableOffset = findOffset(
			(u32*)ndsHeader->arm7destination, 0x00010000,//ndsHeader->arm7binarySize,
			swiGetPitchTableSignature1Alt2, 4
		);
		if (swiGetPitchTableOffset) {
			dbg_printf("swiGetPitchTable SDK <= 2 call alt 2 found\n");
		} else {
			dbg_printf("swiGetPitchTable SDK <= 2 call alt 2 not found\n");
		}
	}
	if (!swiGetPitchTableOffset) {
		swiGetPitchTableOffset = findOffset(
			(u32*)ndsHeader->arm7destination, 0x00010000,//ndsHeader->arm7binarySize,
			swiGetPitchTableSignature1Alt3, 4
		);
		if (swiGetPitchTableOffset) {
			dbg_printf("swiGetPitchTable SDK <= 2 call alt 3 found\n");
		} else {
			dbg_printf("swiGetPitchTable SDK <= 2 call alt 3 not found\n");
		}
	}
	if (!swiGetPitchTableOffset) {
		swiGetPitchTableOffset = findOffset(
			(u32*)ndsHeader->arm7destination, 0x00010000,//ndsHeader->arm7binarySize,
			swiGetPitchTableSignature1Alt4, 3
		);
		if (swiGetPitchTableOffset) {
			dbg_printf("swiGetPitchTable SDK <= 2 call alt 4 found\n");
		} else {
			dbg_printf("swiGetPitchTable SDK <= 2 call alt 4 not found\n");
		}
	}
	if (!swiGetPitchTableOffset) {
		swiGetPitchTableOffset = findOffset(
			(u32*)ndsHeader->arm7destination, 0x00010000,//ndsHeader->arm7binarySize,
			swiGetPitchTableSignature1Alt5, 3
		);
		if (swiGetPitchTableOffset) {
			dbg_printf("swiGetPitchTable SDK <= 2 call alt 5 found\n");
		} else {
			dbg_printf("swiGetPitchTable SDK <= 2 call alt 5 not found\n");
		}
	}
	if (!swiGetPitchTableOffset) {
		swiGetPitchTableOffset = findOffset(
			(u32*)ndsHeader->arm7destination, 0x00010000,//ndsHeader->arm7binarySize,
			swiGetPitchTableSignature1Alt6, 3
		);
		if (swiGetPitchTableOffset) {
			dbg_printf("swiGetPitchTable SDK <= 2 call alt 6 found\n");
		} else {
			dbg_printf("swiGetPitchTable SDK <= 2 call alt 6 not found\n");
		}
	}
	if (!swiGetPitchTableOffset) {
		swiGetPitchTableOffset = findOffset(
			(u32*)ndsHeader->arm7destination, 0x00010000,//ndsHeader->arm7binarySize,
			swiGetPitchTableSignature1Alt7, 3
		);
		if (swiGetPitchTableOffset) {
			dbg_printf("swiGetPitchTable SDK <= 2 call alt 7 found\n");
		} else {
			dbg_printf("swiGetPitchTable SDK <= 2 call alt 7 not found\n");
		}
	}
	if (!swiGetPitchTableOffset) {
		swiGetPitchTableOffset = findOffset(
			(u32*)ndsHeader->arm7destination, 0x00010000,//ndsHeader->arm7binarySize,
			swiGetPitchTableSignature1Alt8, 3
		);
		if (swiGetPitchTableOffset) {
			dbg_printf("swiGetPitchTable SDK <= 2 call alt 8 found\n");
		} else {
			dbg_printf("swiGetPitchTable SDK <= 2 call alt 8 not found\n");
		}
	}
	if (!swiGetPitchTableOffset) {
		swiGetPitchTableOffset = findOffset(
			(u32*)ndsHeader->arm7destination, 0x00010000,//ndsHeader->arm7binarySize,
			swiGetPitchTableSignature1Alt9, 3
		);
		if (swiGetPitchTableOffset) {
			dbg_printf("swiGetPitchTable SDK <= 2 call alt 9 found\n");
		} else {
			dbg_printf("swiGetPitchTable SDK <= 2 call alt 9 not found\n");
		}
	}
	if (!swiGetPitchTableOffset) {
		swiGetPitchTableOffset = findOffset(
			(u32*)ndsHeader->arm7destination, 0x00010000,//ndsHeader->arm7binarySize,
			swiGetPitchTableSignature3, 3
		);
		if (swiGetPitchTableOffset) {
			dbg_printf("swiGetPitchTable SDK 3 call found\n");
		} else {
			dbg_printf("swiGetPitchTable SDK 3 call not found\n");
		}
	}
	if (!swiGetPitchTableOffset) {
		swiGetPitchTableOffset = findOffset(
			(u32*)ndsHeader->arm7destination, 0x00010000,//ndsHeader->arm7binarySize,
			swiGetPitchTableSignature3Alt1, 3
		);
		if (swiGetPitchTableOffset) {
			dbg_printf("swiGetPitchTable SDK 3 call alt 1 found\n");
		} else {
			dbg_printf("swiGetPitchTable SDK 3 call alt 1 not found\n");
		}
	}
	if (!swiGetPitchTableOffset) {
		swiGetPitchTableOffset = findOffset(
			(u32*)ndsHeader->arm7destination, 0x00010000,//ndsHeader->arm7binarySize,
			swiGetPitchTableSignature3Alt2, 3
		);
		if (swiGetPitchTableOffset) {
			dbg_printf("swiGetPitchTable SDK 3 call alt 2 found\n");
		} else {
			dbg_printf("swiGetPitchTable SDK 3 call alt 2 not found\n");
		}
	}
	if (!swiGetPitchTableOffset) {
		swiGetPitchTableOffset = findOffset(
			(u32*)ndsHeader->arm7destination, 0x00010000,//ndsHeader->arm7binarySize,
			swiGetPitchTableSignature3Alt3, 3
		);
		if (swiGetPitchTableOffset) {
			dbg_printf("swiGetPitchTable SDK 3 call alt 3 found\n");
		} else {
			dbg_printf("swiGetPitchTable SDK 3 call alt 3 not found\n");
		}
	}
	if (!swiGetPitchTableOffset) {
		swiGetPitchTableOffset = findOffset(
			(u32*)ndsHeader->arm7destination, 0x00010000,//ndsHeader->arm7binarySize,
			swiGetPitchTableSignature3Alt4, 3
		);
		if (swiGetPitchTableOffset) {
			dbg_printf("swiGetPitchTable SDK 3 call alt 4 found\n");
		} else {
			dbg_printf("swiGetPitchTable SDK 3 call alt 4 not found\n");
		}
	}
	if (!swiGetPitchTableOffset) {
		swiGetPitchTableOffset = findOffset(
			(u32*)ndsHeader->arm7destination, 0x00010000,//ndsHeader->arm7binarySize,
			swiGetPitchTableSignature3Alt5, 3
		);
		if (swiGetPitchTableOffset) {
			dbg_printf("swiGetPitchTable SDK 3 call alt 5 found\n");
		} else {
			dbg_printf("swiGetPitchTable SDK 3 call alt 5 not found\n");
		}
	}
	if (!swiGetPitchTableOffset) {
		swiGetPitchTableOffset = findOffset(
			(u32*)ndsHeader->arm7destination, 0x00010000,//ndsHeader->arm7binarySize,
			swiGetPitchTableSignature3Alt6, 3
		);
		if (swiGetPitchTableOffset) {
			dbg_printf("swiGetPitchTable SDK 3 call alt 6 found\n");
		} else {
			dbg_printf("swiGetPitchTable SDK 3 call alt 6 not found\n");
		}
	}
	if (!swiGetPitchTableOffset) {
		swiGetPitchTableOffset = findOffset(
			(u32*)ndsHeader->arm7destination, 0x00010000,//ndsHeader->arm7binarySize,
			swiGetPitchTableSignature3Alt7, 3
		);
		if (swiGetPitchTableOffset) {
			dbg_printf("swiGetPitchTable SDK 3 call alt 7 found\n");
		} else {
			dbg_printf("swiGetPitchTable SDK 3 call alt 7 not found\n");
		}
	}
	if (!swiGetPitchTableOffset) {
		swiGetPitchTableOffset = findOffset(
			(u32*)ndsHeader->arm7destination, 0x00010000,//ndsHeader->arm7binarySize,
			swiGetPitchTableSignature3Alt8, 3
		);
		if (swiGetPitchTableOffset) {
			dbg_printf("swiGetPitchTable SDK 3 call alt 8 found\n");
		} else {
			dbg_printf("swiGetPitchTable SDK 3 call alt 8 not found\n");
		}
	}
	if (!swiGetPitchTableOffset) {
		swiGetPitchTableOffset = findOffset(
			(u32*)ndsHeader->arm7destination, 0x00010000,//ndsHeader->arm7binarySize,
			swiGetPitchTableSignature3Alt9, 3
		);
		if (swiGetPitchTableOffset) {
			dbg_printf("swiGetPitchTable SDK 3 call alt 9 found\n");
		} else {
			dbg_printf("swiGetPitchTable SDK 3 call alt 9 not found\n");
		}
	}
	if (!swiGetPitchTableOffset) {
		swiGetPitchTableOffset = findOffset(
			(u32*)ndsHeader->arm7destination, 0x00010000,//ndsHeader->arm7binarySize,
			swiGetPitchTableSignature3Alt10, 3
		);
		if (swiGetPitchTableOffset) {
			dbg_printf("swiGetPitchTable SDK 3 call alt 10 found\n");
		} else {
			dbg_printf("swiGetPitchTable SDK 3 call alt 10 not found\n");
		}
	}
	if (!swiGetPitchTableOffset) {
		swiGetPitchTableOffset = findOffset(
			(u32*)ndsHeader->arm7destination, 0x00010000,//ndsHeader->arm7binarySize,
			swiGetPitchTableSignature3Alt11, 3
		);
		if (swiGetPitchTableOffset) {
			dbg_printf("swiGetPitchTable SDK 3 call alt 11 found\n");
		} else {
			dbg_printf("swiGetPitchTable SDK 3 call alt 11 not found\n");
		}
	}
	if (!swiGetPitchTableOffset) {
		swiGetPitchTableOffset = findOffset(
			(u32*)ndsHeader->arm7destination, 0x00010000,//ndsHeader->arm7binarySize,
			swiGetPitchTableSignature4, 3
		);
		if (swiGetPitchTableOffset) {
			dbg_printf("swiGetPitchTable SDK 4 call found\n");
		} else {
			dbg_printf("swiGetPitchTable SDK 4 call not found\n");
		}
	}
	if (!swiGetPitchTableOffset) {
		swiGetPitchTableOffset = findOffset(
			(u32*)ndsHeader->arm7destination, 0x00010000,//ndsHeader->arm7binarySize,
			swiGetPitchTableSignature4Alt1, 3
		);
		if (swiGetPitchTableOffset) {
			dbg_printf("swiGetPitchTable SDK 4 call alt 1 found\n");
		} else {
			dbg_printf("swiGetPitchTable SDK 4 call alt 1 not found\n");
		}
	}
	if (!swiGetPitchTableOffset) {
		swiGetPitchTableOffset = findOffset(
			(u32*)ndsHeader->arm7destination, 0x00010000,//ndsHeader->arm7binarySize,
			swiGetPitchTableSignature4Alt2, 3
		);
		if (swiGetPitchTableOffset) {
			dbg_printf("swiGetPitchTable SDK 4 call alt 2 found\n");
		} else {
			dbg_printf("swiGetPitchTable SDK 4 call alt 2 not found\n");
		}
	}
	if (!swiGetPitchTableOffset) {
		swiGetPitchTableOffset = findOffset(
			(u32*)ndsHeader->arm7destination, 0x00010000,//ndsHeader->arm7binarySize,
			swiGetPitchTableSignature4Alt3, 3
		);
		if (swiGetPitchTableOffset) {
			dbg_printf("swiGetPitchTable SDK 4 call alt 3 found\n");
		} else {
			dbg_printf("swiGetPitchTable SDK 4 call alt 3 not found\n");
		}
	}
	if (!swiGetPitchTableOffset) {
		swiGetPitchTableOffset = findOffset(
			(u32*)ndsHeader->arm7destination, 0x00010000,//ndsHeader->arm7binarySize,
			swiGetPitchTableSignature4Alt4, 3
		);
		if (swiGetPitchTableOffset) {
			dbg_printf("swiGetPitchTable SDK 4 call alt 4 found\n");
		} else {
			dbg_printf("swiGetPitchTable SDK 4 call alt 4 not found\n");
		}
	}
	if (!swiGetPitchTableOffset) {
		swiGetPitchTableOffset = findOffset(
			(u32*)ndsHeader->arm7destination, 0x00010000,//ndsHeader->arm7binarySize,
			swiGetPitchTableSignature4Alt5, 3
		);
		if (swiGetPitchTableOffset) {
			dbg_printf("swiGetPitchTable SDK 4 call alt 5 found\n");
		} else {
			dbg_printf("swiGetPitchTable SDK 4 call alt 5 not found\n");
		}
	}
	if (!swiGetPitchTableOffset) {
		swiGetPitchTableOffset = findOffset(
			(u32*)ndsHeader->arm7destination, 0x00010000,//ndsHeader->arm7binarySize,
			swiGetPitchTableSignature4Alt6, 3
		);
		if (swiGetPitchTableOffset) {
			dbg_printf("swiGetPitchTable SDK 4 call alt 6 found\n");
		} else {
			dbg_printf("swiGetPitchTable SDK 4 call alt 6 not found\n");
		}
	}
	if (!swiGetPitchTableOffset) {
		swiGetPitchTableOffset = findOffset(
			(u32*)ndsHeader->arm7destination, 0x00010000,//ndsHeader->arm7binarySize,
			swiGetPitchTableSignature4Alt7, 3
		);
		if (swiGetPitchTableOffset) {
			dbg_printf("swiGetPitchTable SDK 4 call alt 7 found\n");
		} else {
			dbg_printf("swiGetPitchTable SDK 4 call alt 7 not found\n");
		}
	}
	if (!swiGetPitchTableOffset) {
		swiGetPitchTableOffset = findOffset(
			(u32*)ndsHeader->arm7destination, 0x00010000,//ndsHeader->arm7binarySize,
			swiGetPitchTableSignature4Alt8, 3
		);
		if (swiGetPitchTableOffset) {
			dbg_printf("swiGetPitchTable SDK 4 call alt 8 found\n");
		} else {
			dbg_printf("swiGetPitchTable SDK 4 call alt 8 not found\n");
		}
	}

	if (!swiGetPitchTableOffset) {
		swiGetPitchTableOffset = findOffset(
			(u32*)ndsHeader->arm7destination, 0x00010000,//ndsHeader->arm7binarySize,
			swiGetPitchTableSignature4Alt9, 3
		);
		if (swiGetPitchTableOffset) {
			dbg_printf("swiGetPitchTable SDK 4 call alt 9 found\n");
		} else {
			dbg_printf("swiGetPitchTable SDK 4 call alt 9 not found\n");
		}
	}

	dbg_printf("\n");
	return swiGetPitchTableOffset;
}

u32* findSleepPatchOffset(const tNDSHeader* ndsHeader) {
	dbg_printf("findSleepPatchOffset:\n");

	u32* sleepPatchOffset = findOffset(
		(u32*)ndsHeader->arm7destination, ndsHeader->arm7binarySize,
		sleepPatch, 2
	);
	if (sleepPatchOffset) {
		dbg_printf("Sleep patch found: ");
	} else {
		dbg_printf("Sleep patch not found\n");
	}

	if (sleepPatchOffset) {
		dbg_hexa((u32)sleepPatchOffset);
		dbg_printf("\n");
	}

	dbg_printf("\n");
	return sleepPatchOffset;
}

u16* findSleepPatchOffsetThumb(const tNDSHeader* ndsHeader) {
	dbg_printf("findSleepPatchOffsetThumb:\n");
	
	u16* sleepPatchOffset = findOffsetThumb(
		(u16*)ndsHeader->arm7destination, ndsHeader->arm7binarySize,
		sleepPatchThumb, 2
	);
	if (sleepPatchOffset) {
		dbg_printf("Thumb sleep patch thumb found: ");
	} else {
		dbg_printf("Thumb sleep patch thumb not found\n");
	}

	if (!sleepPatchOffset) {
		sleepPatchOffset = findOffsetThumb(
			(u16*)ndsHeader->arm7destination, ndsHeader->arm7binarySize,
			sleepPatchThumbAlt, 2
		);
		if (sleepPatchOffset) {
			dbg_printf("Thumb sleep patch thumb alt found: ");
		} else {
			dbg_printf("Thumb sleep patch thumb alt not found\n");
		}
	}

	if (sleepPatchOffset) {
		dbg_hexa((u32)sleepPatchOffset);
		dbg_printf("\n");
	}

	dbg_printf("\n");
	return sleepPatchOffset;
}

/*u32* findRamClearOffset(const tNDSHeader* ndsHeader) {
	dbg_printf("findRamClearOffset:\n");

	u32* ramClearOffset = findOffset(
		(u32*)ndsHeader->arm7destination, ndsHeader->arm7binarySize,
		ramClearSignature, 2
	);
	if (ramClearOffset) {
		dbg_printf("RAM clear found: ");
		dbg_hexa((u32)ramClearOffset);
		dbg_printf("\n");
	} else {
		dbg_printf("RAM clear not found\n");
	}

	dbg_printf("\n");
	return ramClearOffset;
}*/

u32* findCardCheckPullOutOffset(const tNDSHeader* ndsHeader, const module_params_t* moduleParams) {
	dbg_printf("findCardCheckPullOutOffset:\n");
	
	const u32* cardCheckPullOutSignature = cardCheckPullOutSignature1;
    if (moduleParams->sdk_version > 0x2004FFF && moduleParams->sdk_version < 0x3000000) {
		cardCheckPullOutSignature = cardCheckPullOutSignature2;
    } else if (moduleParams->sdk_version > 0x3000000 && moduleParams->sdk_version < 0x4000000) {
		cardCheckPullOutSignature = cardCheckPullOutSignature3;
	}

	u32* cardCheckPullOutOffset = findOffset(
		(u32*)ndsHeader->arm7destination, ndsHeader->arm7binarySize,
		cardCheckPullOutSignature, 4
	);
	if (cardCheckPullOutOffset) {
		dbg_printf("Card check pull out found: ");
	} else {
		dbg_printf("Card check pull out not found\n");
	}

	if (cardCheckPullOutOffset) {
		dbg_hexa((u32)cardCheckPullOutOffset);
		dbg_printf("\n");
	}

	dbg_printf("\n");
	return cardCheckPullOutOffset;
}

u32* findCardIrqEnableOffset(const tNDSHeader* ndsHeader, const module_params_t* moduleParams) {
	dbg_printf("findCardIrqEnableOffset:\n");
	
	const u32* irqEnableStartSignature = irqEnableStartSignature1;
	if (moduleParams->sdk_version > 0x4000000) {
		irqEnableStartSignature = irqEnableStartSignature4;
	}

	u32* cardIrqEnableOffset = findOffset(
		(u32*)ndsHeader->arm7destination, ndsHeader->arm7binarySize,
		irqEnableStartSignature, 4
	);
	if (cardIrqEnableOffset) {
		dbg_printf("irq enable found\n");
	} else {
		dbg_printf("irq enable not found\n");
	}

	if (!cardIrqEnableOffset) {
		// SDK 5
		cardIrqEnableOffset = findOffset(
			(u32*)ndsHeader->arm7destination, ndsHeader->arm7binarySize,
            irqEnableStartSignature4Alt, 4
		);
		if (cardIrqEnableOffset) {
			dbg_printf("irq enable alt found\n");
		} else {
			dbg_printf("irq enable alt not found\n");
		}
	}

	if (!cardIrqEnableOffset && isSdk5(moduleParams)) {
		// SDK 5
		cardIrqEnableOffset = (u32*)findOffsetThumb(
			(u32*)ndsHeader->arm7destination, ndsHeader->arm7binarySize,
            irqEnableStartSignatureThumb5, 5
		);
		if (cardIrqEnableOffset) {
			dbg_printf("irq enable thumb found\n");
		} else {
			dbg_printf("irq enable thumb not found\n");
		}
	}

	dbg_printf("\n");
	return cardIrqEnableOffset;
}

u32* findSdCardResetOffset(const tNDSHeader* ndsHeader, const module_params_t* moduleParams) {
	dbg_printf("findSdCardResetOffset:\n");

	u32* sdCardResetOffset = findOffset(
		(u32*)__DSiHeader->arm7idestination, __DSiHeader->arm7ibinarySize,
		sdCardResetSignatureType1, 4
	);

	if (!sdCardResetOffset) {
		sdCardResetOffset = findOffset(
			(u32*)__DSiHeader->arm7idestination, __DSiHeader->arm7ibinarySize,
			sdCardResetSignatureType2, 4
		);
	}

	if (!sdCardResetOffset) {
		sdCardResetOffset = findOffset(
			(u32*)__DSiHeader->arm7idestination, __DSiHeader->arm7ibinarySize,
			sdCardResetSignatureType3, 4
		);
	}

	if (!sdCardResetOffset) {
		sdCardResetOffset = findOffset(
			(u32*)__DSiHeader->arm7idestination, __DSiHeader->arm7ibinarySize,
			sdCardResetSignatureType4, 4
		);
	}

	if (!sdCardResetOffset) {
		sdCardResetOffset = (u32*)findOffsetThumb(
			(u32*)__DSiHeader->arm7idestination, __DSiHeader->arm7ibinarySize,
			sdCardResetSignatureThumbType1, 7
		);
	}

	if (!sdCardResetOffset) {
		sdCardResetOffset = (u32*)findOffsetThumb(
			(u32*)__DSiHeader->arm7idestination, __DSiHeader->arm7ibinarySize,
			sdCardResetSignatureThumbType2, 7
		);
	}

	if (!sdCardResetOffset) {
		sdCardResetOffset = (u32*)findOffsetThumb(
			(u32*)__DSiHeader->arm7idestination, __DSiHeader->arm7ibinarySize,
			sdCardResetSignatureThumbType3, 7
		);
	}

	if (!sdCardResetOffset) {
		sdCardResetOffset = (u32*)findOffsetThumb(
			(u32*)__DSiHeader->arm7idestination, __DSiHeader->arm7ibinarySize,
			sdCardResetSignatureThumbType4, 7
		);
	}

	if (sdCardResetOffset) {
		dbg_printf("SD Card reset found\n");
	} else {
		dbg_printf("SD Card reset not found\n");
	}

	dbg_printf("\n");
	return sdCardResetOffset;
}
