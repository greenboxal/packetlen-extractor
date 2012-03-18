#include "memorytools.h"
#include <string.h>
#include <memory.h>
#include <stdarg.h>
#include <stdlib.h>

char *defaultStartAddress;
char *defaultEndAddress;

void InitializeMemoryTools(char *startAddress, char *endAddress)
{
	defaultStartAddress = startAddress;
	defaultEndAddress = endAddress;
}

struct PatternPart
{
	char value;
	char flags;
	int size;
	void *saveTo;
};

// A-F0-9 match exact byte
// ?[x][y] act as wild card where x can be:
// b = 1 byte
// w = 2 bytes
// d = 4 bytes
// q = 8 bytes
// a = 4 bytes(when extracting, will be converted to a real address)
// n = n bytes
// and y can be:
// x: extract the value of the matched area in the next va arg
// p: extract the address of the matched area in the next va arg
char *VFindPattern(char *startAddress, char *endAddress, char *pattern, va_list args)
{
	int patternLen = strlen(pattern);
	char buffer[255]; int bufferLen = 0;
	
	struct PatternPart *compiledPattern = NULL;
	int compiledPatternSize = 0;

	for (int i = 0; i <= patternLen; i++)
	{
		if (pattern[i] == ' ' || i == patternLen)
		{
			buffer[bufferLen] = 0;
			bufferLen = 0;

			compiledPatternSize++;
			compiledPattern = (struct PatternPart *)realloc(compiledPattern, compiledPatternSize * sizeof(struct PatternPart));

			struct PatternPart *me = &compiledPattern[compiledPatternSize - 1];
			memset(me, 0, sizeof(struct PatternPart));

			if (buffer[0] == '?')
			{
				switch (buffer[1])
				{
				case 'b':
					me->size = 1;
					break;
				case 'w':
					me->size = 2;
					break;
				case 'd':
					me->size = 4;
					break;
				case 'q':
					me->size = 8;
					break;
				case 'a':
					me->size = -2;
					break;
				default:
					me->size = (int)strtoul(&buffer[1], NULL, 10);
					break;
				}

				if (buffer[2] == 'x')
				{
					me->saveTo = va_arg(args, void *);
						
					if (me->size == -2)
					{
						me->size = 4;
						me->flags = 2;
					}
				}
				else if (buffer[2] == 'p')
				{
					me->saveTo = va_arg(args, void *);
						
					me->flags = 3;
				}
				else
				{
					me->flags = 1;
				}
			}
			else
			{
				me->value = (char)strtoul(buffer, NULL, 16);
			}
		}
		else
		{
			buffer[bufferLen++] = pattern[i];
		}
	}

	for (char *p = startAddress; p < endAddress; p++)
	{
		int offset = 0;
		bool match = true;
		buffer[0] = 0;
		bufferLen = 0;

		for (int i = 0; i < compiledPatternSize; i++)
		{
			struct PatternPart *me = &compiledPattern[i];
			bool fail = false;

			if (&p[offset] > endAddress)
			{
				match = false;
				break;
			}

			switch (me->flags)
			{
			case 0:
				if (p[offset++] != me->value)
					fail = true;
				break;
			case 1:
				offset += me->size;
				break;
			case 2:
				if (me->size > 0)
				{
					memcpy(me->saveTo, &p[offset], me->size);
					offset += me->size;
				}
				else if (me->size == -2)
				{
					unsigned int *arg = (unsigned int *)me->saveTo;

					*arg = *((unsigned int*)&p[offset]);
					*arg += (unsigned int)(&p[offset] + 4);

					offset += 4;
				}
				break;
			case 3:
				unsigned int *arg = (unsigned int *)me->saveTo;

				*arg = (unsigned int)(&p[offset - 1]);

				offset += me->size;
				break;
			}

			if (fail)
			{
				match = false;
				break;
			}
		}

		if (match)
		{
			if (compiledPattern)
				free(compiledPattern);

			return p;
		}
	}
	
	if (compiledPattern)
		free(compiledPattern);

	return 0;
}

char *GaFindPatternEx(char *startAddress, char *endAddress, char *pattern, ...)
{
	va_list args;

	va_start(args, pattern);
	char *result = VFindPattern(startAddress, endAddress, pattern, args);
	va_end(args);

	return result;
}

char *GaFindPattern(char *pattern, ...)
{
	va_list args;

	va_start(args, pattern);
	char *result = VFindPattern(defaultStartAddress, defaultEndAddress, pattern, args);
	va_end(args);

	return result;
}
