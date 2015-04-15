#include "stdafx.h"
#include <Windows.h>

//TODO: these tests are very crappy. Once VM instrumentation is in place, write test cases with actual malware.

LPVOID loadStringToMemory(HANDLE process, const wchar_t* str)
{
	LPVOID argAddress = VirtualAllocEx(process, NULL, wcslen(str) * 2, MEM_COMMIT, PAGE_READWRITE);
	if (!argAddress)
		return 0;
	if (!WriteProcessMemory(process, argAddress, str, wcslen(str) * 2, NULL))
		return 0;
	return argAddress;
}
bool injectDLL(HANDLE process, const wchar_t* dllName)
{
	LPVOID loadLibAddress = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW");
	LPVOID nameAddress = loadStringToMemory(process, dllName);

	if (!nameAddress || !loadLibAddress)
		return false;

	HANDLE creationThread = CreateRemoteThread(process, NULL, NULL,
												static_cast<LPTHREAD_START_ROUTINE>(loadLibAddress),
												nameAddress, NULL, NULL);
	
	if (creationThread)
	{
		WaitForSingleObject(creationThread, INFINITE);
		
		DWORD ret;
		GetExitCodeThread(creationThread, &ret);
		CloseHandle(creationThread);
		
		return (ret != NULL);
	}
	else
		return false;
}

BYTE codeCave[6] = {
		0x90, 0x90, 0x90, 0x90, 0x90, 0xC3
};


void testLocalUnpack()
{
    LoadLibraryA("PackerAttackerHook.dll");

    LPVOID _codeCave = VirtualAlloc(NULL, 6, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(GetCurrentProcess(), _codeCave, &codeCave[0], 6, NULL);

    __asm {
        MOV EAX, [_codeCave]
        CALL EAX
    }

    system("pause");
}

void testUpx()
{
    STARTUPINFOA StartupInfo = {0};
    PROCESS_INFORMATION ProcessInformation;
 
    // initialize the structures
    StartupInfo.cb = sizeof(StartupInfo);
 
    // attempt to load the specified target
    if (CreateProcessA("br_challenge.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &StartupInfo, &ProcessInformation))
    {
        injectDLL(ProcessInformation.hProcess, L"PackerAttackerHook.dll");
        ResumeThread(ProcessInformation.hThread);
        WaitForSingleObject(ProcessInformation.hThread, INFINITE);
    }
    else
        printf("Failed to execute binary!\n");

    system("pause");
}

unsigned char memoryToWrite[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZnowiknowmyabcsnexttimewontyousingwithme";

void testWriteProcessMemorySimple()
{
    LoadLibraryA("PackerAttackerHook.dll");

    STARTUPINFOA StartupInfo = {0};
    PROCESS_INFORMATION ProcessInformation;
 
    // initialize the structures
    StartupInfo.cb = sizeof(StartupInfo);
 
    // attempt to load the specified target
    if (CreateProcessA("C:\\Users\\nick.cano\\Documents\\Visual Studio 2010\\Projects\\ThePackerAttacker\\Debug\\PackerAttackTestDummy.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &StartupInfo, &ProcessInformation))
    {
        printf("executed binary!\n");
        auto mem = VirtualAllocEx(ProcessInformation.hProcess, NULL, sizeof(memoryToWrite), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        WriteProcessMemory(ProcessInformation.hProcess, mem, &memoryToWrite[0], sizeof(memoryToWrite), NULL);

        WaitForSingleObject(ProcessInformation.hThread, INFINITE);
    }
    else
        printf("Failed to execute binary! GetLastError() == %d\n", GetLastError());

    system("pause");
}

void testWriteProcessMemoryComplex()
{
    LoadLibraryA("PackerAttackerHook.dll");

    STARTUPINFOA StartupInfo = {0};
    PROCESS_INFORMATION ProcessInformation;
 
    // initialize the structures
    StartupInfo.cb = sizeof(StartupInfo);
 
    // attempt to load the specified target
    if (CreateProcessA("C:\\Users\\nick.cano\\Documents\\Visual Studio 2010\\Projects\\ThePackerAttacker\\Debug\\PackerAttackTestDummy.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &StartupInfo, &ProcessInformation))
    {
        printf("executed binary!\n");
        auto mem = VirtualAllocEx(ProcessInformation.hProcess, NULL, sizeof(memoryToWrite), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        for (unsigned int i = 0; i < sizeof(memoryToWrite) - 4; i++)
            WriteProcessMemory(ProcessInformation.hProcess, (LPVOID)((DWORD)mem + i), &memoryToWrite[i], 4, NULL);

        WaitForSingleObject(ProcessInformation.hThread, INFINITE);
    }
    else
        printf("Failed to execute binary! GetLastError() == %d\n", GetLastError());

    system("pause");
}

int _tmain(int argc, _TCHAR* argv[])
{
    //testLocalUnpack();
    //testUpx();
    //testWriteProcessMemorySimple();
    testWriteProcessMemoryComplex();
	return 0;
}

