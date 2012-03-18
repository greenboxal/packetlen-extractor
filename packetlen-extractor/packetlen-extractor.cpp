#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <map>

#include "MemoryTools.h"

using namespace std;

struct PacketLenStruct
{ 
	struct PacketLenStruct *left, *parent, *right; 
	unsigned int key; 
	int value; 
};

map<int, int> packets;

void EnableDebugPrivileges() 
{
	TOKEN_PRIVILEGES NewState, PreviousState;
	HANDLE hCurrent, hToken;
	DWORD ReturnLength;
	BOOL bRet;
	LUID luid;

	hCurrent = GetCurrentProcess();
	bRet = OpenProcessToken(hCurrent, 40, &hToken);

	bRet = LookupPrivilegeValue(NULL, "SeDebugPrivilege", &luid);


	NewState.PrivilegeCount = 1;
	NewState.Privileges[0].Luid = luid;
	NewState.Privileges[0].Attributes= 2;

	AdjustTokenPrivileges(hToken, FALSE, &NewState, 28, &PreviousState, &ReturnLength);
}

void SetHWBP(HANDLE hThread, unsigned long uAddress)
{
	CONTEXT c = {CONTEXT_DEBUG_REGISTERS};

	SuspendThread(hThread);
	GetThreadContext(hThread, &c);
	
	c.Dr0 = uAddress;
	c.Dr7 = (1 << 0);
	c.Dr6 = 0;

	SetThreadContext(hThread, &c);
	ResumeThread(hThread);
}

void RemoveHWBP(HANDLE hThread)
{
	SetHWBP(hThread, 0);
}

void SimpleRPM(HANDLE p, DWORD f, char *t, int s)
{
	SIZE_T read = 0;

	ReadProcessMemory(p, (LPCVOID)f, (LPVOID)t, (SIZE_T)s, &read);
}

unsigned char *SkipInstruction(unsigned char *func) 
{
    if (*func != 0xCC)
    {
        // Skip prefixes F0h, F2h, F3h, 66h, 67h, D8h-DFh, 2Eh, 36h, 3Eh, 26h, 64h and 65h
        int operandSize = 4;
        int FPU = 0;
        while(*func == 0xF0 || 
              *func == 0xF2 || 
              *func == 0xF3 || 
             (*func & 0xFC) == 0x64 || 
             (*func & 0xF8) == 0xD8 ||
             (*func & 0x7E) == 0x62)
        { 
            if(*func == 0x66) 
            { 
                operandSize = 2; 
            }
            else if((*func & 0xF8) == 0xD8) 
            {
                FPU = *func++;
                break;
            }

            func++;
        }

        // Skip two-byte opcode byte 
        bool twoByte = false; 
        if(*func == 0x0F) 
        { 
            twoByte = true; 
            func++; 
        } 

        // Skip opcode byte 
        unsigned char opcode = *func++; 

        // Skip mod R/M byte 
        unsigned char modRM = 0xFF; 
        if(FPU) 
        { 
            if((opcode & 0xC0) != 0xC0) 
            { 
                modRM = opcode; 
            } 
        } 
        else if(!twoByte) 
        { 
            if((opcode & 0xC4) == 0x00 || 
               (opcode & 0xF4) == 0x60 && ((opcode & 0x0A) == 0x02 || (opcode & 0x09) == 0x9) || 
               (opcode & 0xF0) == 0x80 || 
               (opcode & 0xF8) == 0xC0 && (opcode & 0x0E) != 0x02 || 
               (opcode & 0xFC) == 0xD0 || 
               (opcode & 0xF6) == 0xF6) 
            { 
                modRM = *func++; 
            } 
        } 
        else 
        { 
            if((opcode & 0xF0) == 0x00 && (opcode & 0x0F) >= 0x04 && (opcode & 0x0D) != 0x0D || 
               (opcode & 0xF0) == 0x30 || 
               opcode == 0x77 || 
               (opcode & 0xF0) == 0x80 || 
               (opcode & 0xF0) == 0xA0 && (opcode & 0x07) <= 0x02 || 
               (opcode & 0xF8) == 0xC8) 
            { 
                // No mod R/M byte 
            } 
            else 
            { 
                modRM = *func++; 
            } 
        } 

        // Skip SIB
        if((modRM & 0x07) == 0x04 &&
           (modRM & 0xC0) != 0xC0)
        {
            func += 1;   // SIB
        }

        // Skip displacement
        if((modRM & 0xC5) == 0x05) func += 4;   // Dword displacement, no base 
        if((modRM & 0xC0) == 0x40) func += 1;   // Byte displacement 
        if((modRM & 0xC0) == 0x80) func += 4;   // Dword displacement 

        // Skip immediate 
        if(FPU) 
        { 
            // Can't have immediate operand 
        } 
        else if(!twoByte) 
        { 
            if((opcode & 0xC7) == 0x04 || 
               (opcode & 0xFE) == 0x6A ||   // PUSH/POP/IMUL 
               (opcode & 0xF0) == 0x70 ||   // Jcc 
               opcode == 0x80 || 
               opcode == 0x83 || 
               (opcode & 0xFD) == 0xA0 ||   // MOV 
               opcode == 0xA8 ||            // TEST 
               (opcode & 0xF8) == 0xB0 ||   // MOV
               (opcode & 0xFE) == 0xC0 ||   // RCL 
               opcode == 0xC6 ||            // MOV 
               opcode == 0xCD ||            // INT 
               (opcode & 0xFE) == 0xD4 ||   // AAD/AAM 
               (opcode & 0xF8) == 0xE0 ||   // LOOP/JCXZ 
               opcode == 0xEB || 
               opcode == 0xF6 && (modRM & 0x30) == 0x00)   // TEST 
            { 
                func += 1; 
            } 
            else if((opcode & 0xF7) == 0xC2) 
            { 
                func += 2;   // RET 
            } 
            else if((opcode & 0xFC) == 0x80 || 
                    (opcode & 0xC7) == 0x05 || 
                    (opcode & 0xF8) == 0xB8 ||
                    (opcode & 0xFE) == 0xE8 ||      // CALL/Jcc 
                    (opcode & 0xFE) == 0x68 || 
                    (opcode & 0xFC) == 0xA0 || 
                    (opcode & 0xEE) == 0xA8 || 
                    opcode == 0xC7 || 
                    opcode == 0xF7 && (modRM & 0x30) == 0x00) 
            { 
                func += operandSize; 
            } 
        } 
        else 
        { 
            if(opcode == 0xBA ||            // BT 
               opcode == 0x0F ||            // 3DNow! 
               (opcode & 0xFC) == 0x70 ||   // PSLLW 
               (opcode & 0xF7) == 0xA4 ||   // SHLD 
               opcode == 0xC2 || 
               opcode == 0xC4 || 
               opcode == 0xC5 || 
               opcode == 0xC6) 
            { 
                func += 1; 
            } 
            else if((opcode & 0xF0) == 0x80) 
            {
                func += operandSize;   // Jcc -i
            }
        }
    } 
	else 
		func++;

    return func;
}

extern char *defaultEndAddress;
DWORD FindBPAddr(char *startAddr, char *endAddr, DWORD *end)
{
	unsigned char *packet_start, *packet_end;

	InitializeMemoryTools((char *)startAddr, (char *)endAddr);

	int add = 0;

	packet_start = (unsigned char *)GaFindPattern("C7 44 ?w 87 01 00 00");
	add = 8;

	if (!packet_start) 
	{
		packet_start = (unsigned char *)GaFindPattern("C7 85 ?d 87 01 00 00");
		add = 10;
	}

	if (!packet_start) 
	{
		packet_start = (unsigned char *)GaFindPattern("C7 45 ?b 87 01 00 00");
		add = 7;
	}

	packet_start += add;
	packet_end = (unsigned char *)GaFindPatternEx((char *)packet_start, defaultEndAddress, "8B E5 5D C3");

	int calls = 0;
	while (packet_start < packet_end) 
	{
		if (packet_start[0] == 0xE8) 
		{
			calls++;
			
			if (calls == 10) 
				break;
		}

		if (packet_start[0] == 0xC3)
			break;

		packet_start = SkipInstruction(packet_start);
	}

	*end = (DWORD)(packet_end - (DWORD)startAddr);

	return (DWORD)(packet_start - (DWORD)startAddr);
}

void TraverseStart(HANDLE hProc, DWORD addr);
void Traverse(HANDLE hProc, struct PacketLenStruct *node)
{
	if (node->parent == NULL || node->key == 0 || node->key > 0xFFFF)
		return;

	TraverseStart(hProc, (DWORD)node->left);
	packets[node->key] = node->value;
	TraverseStart(hProc, (DWORD)node->right);
}

void TraverseStart(HANDLE hProc, DWORD addr)
{
	PacketLenStruct *node = new PacketLenStruct();

	SimpleRPM(hProc, addr, (char *)node, sizeof(struct PacketLenStruct));

	Traverse(hProc, node);

	delete node;
}

DWORD FindParent(HANDLE hProc, DWORD addr)
{
	struct PacketLenStruct node;

	//do
	//{
		SimpleRPM(hProc, (DWORD)addr, (char *)&node, sizeof(struct PacketLenStruct));

		if (node.parent != NULL)
			addr = (DWORD)node.parent;
	//}
	//while (node.parent != NULL && node.right != node.parent);

	return addr;
}

void TraverseBegin(HANDLE hProc, DWORD addr)
{
	SimpleRPM(hProc, addr, (char *)&addr, sizeof(DWORD));

	TraverseStart(hProc, FindParent(hProc, addr));
}

void EnterDebugLoop(const LPDEBUG_EVENT de)
{
	DWORD dwState = 0;
	DWORD baseAddr = 0;
	DWORD ecx = 0;
	DWORD finalBp = 0;

	HANDLE hProcess, hThread;

	char *dumpStart = NULL;
	int dumpSize = 0;

	for(;;) 
	{
		DWORD dwContinueStatus = DBG_CONTINUE;
		DWORD dummy;

		WaitForDebugEvent(de, INFINITE); 

		switch (de->dwDebugEventCode) 
		{ 
		case EXCEPTION_DEBUG_EVENT:
			switch(de->u.Exception.ExceptionRecord.ExceptionCode)
			{ 
			case EXCEPTION_BREAKPOINT:
				if (dwState == 1)
				{
					DWORD addr;
					
					dwState++;

					{
						MODULEENTRY32 mod;
						HANDLE hSnapshot;
						BOOL bFound;
					
						mod.dwSize = sizeof(MODULEENTRY32);
						
						hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, de->dwProcessId);
						bFound = Module32First(hSnapshot, &mod);

						if (bFound)
						{
							printf("Found process module at 0x%x(%d bytes).\n", baseAddr, mod.modBaseSize);

							dumpSize = mod.modBaseSize;
							dumpStart = new char[dumpSize];

							SimpleRPM(hProcess, (DWORD)baseAddr, dumpStart, dumpSize);
						}

						CloseHandle(hSnapshot);
					}
					
					addr = FindBPAddr(dumpStart, dumpStart + dumpSize, &finalBp) + baseAddr;
					printf("Packetlen code found at 0x%x, waiting breakpoint...\n", addr);
					
					finalBp += baseAddr;

					SetHWBP(hThread, (unsigned long)addr);
					ResumeThread(hThread);
				}
				break;
			case EXCEPTION_SINGLE_STEP:
				{
					if (dwState == 2)
					{
						printf("Packetlen code reached, extracting packets...\n");
						
						CONTEXT c = {CONTEXT_INTEGER};

						GetThreadContext(hThread, &c);
						ecx = c.Ecx;

						SetHWBP(hThread, (unsigned long)finalBp);

						dwState++;
					}
					else if (dwState == 3)
					{
						TraverseBegin(hProcess, ecx + 4);
						
						RemoveHWBP(hThread);

						return;
					}
				}
				break;
			default:
				dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
				break;
			}
			break;
		case CREATE_PROCESS_DEBUG_EVENT:
			{
				hProcess = de->u.CreateProcessInfo.hProcess;
				hThread = de->u.CreateProcessInfo.hThread;
				baseAddr = (DWORD)de->u.CreateProcessInfo.lpBaseOfImage;
				
				printf("Process started.\n");

				dwState++;
			}
			break;
		case OUTPUT_DEBUG_STRING_EVENT:
			{
				char *msg = new char[de->u.DebugString.nDebugStringLength];

				ReadProcessMemory(hProcess, de->u.DebugString.lpDebugStringData, msg, de->u.DebugString.nDebugStringLength, NULL);
				printf("Debug: %s\n", msg);

				delete msg;
			}
			break;
		default:
			break;
		} 

		ContinueDebugEvent(
			de->dwProcessId, 
			de->dwThreadId, 
			dwContinueStatus);

		if (GetExitCodeProcess(hProcess, &dummy) && GetLastError() == STILL_ACTIVE)
			break;
	}
}

void Usage()
{
	printf("Usage:\n");
	printf("\tpacketlen-extractor <exe file> <output file> <output file type>\n");
	printf("\nWhere output file type could be:");
	printf("\t0: eAthena packet_db.txt format\n");
	printf("\t1: Cronus packetdb.h format\n");
}

int main(int argc, char *argv[])
{
	if (argc < 4)
	{
		Usage();
		return 0;
	}

	char *exe = argv[1];
	char *txt = argv[2];
	int type = atoi(argv[3]);

	if (type != 0 && type != 1)
	{
		Usage();
		return 0;
	}

	printf("Enabling debug privileges...\n");
	EnableDebugPrivileges();

	PROCESS_INFORMATION pi;
	STARTUPINFO si;
	DEBUG_EVENT de;

	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	ZeroMemory(&si, sizeof(STARTUPINFO));

	si.cb = sizeof(STARTUPINFO);

	printf("Creating process...\n");
	if (!CreateProcess(NULL, exe, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &si, &pi))
	{
		printf("Could not start target process.\n");
		return 0;
	}

	de.dwProcessId = pi.dwProcessId;
	de.dwThreadId = pi.dwThreadId;
	
	printf("Starting debug loop...\n");
	EnterDebugLoop((const LPDEBUG_EVENT)&de);

	FILE *fp = fopen(txt, "w");

	if (!fp)
	{
		printf("Could not open output file.\n");
		return 0;
	}

	map<int, int>::iterator it;
	for (it = packets.begin(); it != packets.end(); it++)
	{
		if (type == 0)
		{
			fprintf(fp, "0x%x,%d\n", it->first, it->second);
		}
		else if (type == 1)
		{
			fprintf(fp, "addpacket(0x%x,%d,NULL);\n", it->first, it->second);
		}
	}

	printf("Packetlen extracted.\n");

	fclose(fp);

	return 0;
}
