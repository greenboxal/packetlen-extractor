#pragma once

#define GET_CALL_ADDR(x) ((*(unsigned int*)(x)) - (unsigned int)(x) - 4)
#define MAKE_CALL_ADDR(from, to) ((unsigned int)(to) + (unsigned int)(from) + 4)

extern void InitializeMemoryTools(char *startAddress, char *endAddress);
extern char *GaFindPatternEx(char *startAddress, char *endAddress, char *pattern, ...);
extern char *GaFindPattern(char *pattern, ...);
