#include <Windows.h>

#include <stdio.h>
#include <tchar.h>

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

bool executeProcessAndInjectDll(wchar_t* fileName)
{
    STARTUPINFOW StartupInfo = {0};
    PROCESS_INFORMATION ProcessInformation;
 
    // initialize the structures
    StartupInfo.cb = sizeof(StartupInfo);
 
    // attempt to load the specified target
    if (CreateProcessW(fileName, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &StartupInfo, &ProcessInformation))
    {
        injectDLL(ProcessInformation.hProcess, L"PackerAttackerHook.dll");
        ResumeThread(ProcessInformation.hThread);

        WaitForSingleObject(ProcessInformation.hThread, INFINITE);
        return true;
    }
    else
        return false;
}

int _tmain(int argc, _TCHAR* argv[])
{
    if (argc != 2)
    {
        printf("Usage: me.exe <packed.exe>\n");
        return ERROR_INVALID_PARAMETER;
    }

    if (!executeProcessAndInjectDll(argv[1]))
    {
        printf("Failed to launch process and inject dll!\n");
        return -1;
    }

    printf("Process successfully executed! Check 'C:\\dumps\\' for dumped files.\n");
    printf("    '*.WPM.DMP' files are dumps from WriteProcessMemory\n");
    printf("    '*.DMP' files are dumps of memory that was unexpectedly executed\n");

	return 0;
}