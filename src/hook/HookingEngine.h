#pragma once
#include <Windows.h>
#include <assert.h>
#include <functional>

#include "detours.h"

class HookingEngine
{
public:
    HookingEngine() : inTransaction(false) {}
    ~HookingEngine()  {}

    void doTransaction(std::function<void()> transaction)
    {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        inTransaction = true;
        transaction();
        inTransaction = false;
        DetourTransactionCommit();
    }

    void placeHook(PVOID *hookAt, PVOID callback)
    {
        assert(inTransaction);
        DetourAttach(hookAt, callback);
    }

    void placeShallowExceptionHandlerHook(PVECTORED_EXCEPTION_HANDLER handler)
    {
        assert(inTransaction);
        AddVectoredExceptionHandler(1, handler);
    }

    void placeDeepExceptionHandlerHook(PVECTORED_EXCEPTION_HANDLER handler)
    {
        assert(inTransaction);
        AddVectoredExceptionHandler(0, handler);
    }

    bool injectIntoProcess(HANDLE process, const wchar_t* dllName)
    {
	    LPVOID loadLibAddress = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW");
	    LPVOID nameAddress = this->loadStringToMemory(process, dllName);

	    if (!nameAddress || !loadLibAddress)
		    return false;

	    HANDLE creationThread = CreateRemoteThread(process, NULL, NULL, static_cast<LPTHREAD_START_ROUTINE>(loadLibAddress), nameAddress, NULL, NULL);
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
   
private:
    bool inTransaction;

    LPVOID loadStringToMemory(HANDLE process, const wchar_t* str)
    {
	    LPVOID argAddress = VirtualAllocEx(process, NULL, wcslen(str) * 2, MEM_COMMIT, PAGE_READWRITE);
	    if (!argAddress)
		    return 0;
	    if (!WriteProcessMemory(process, argAddress, str, wcslen(str) * 2, NULL))
		    return 0;
	    return argAddress;
    }

};