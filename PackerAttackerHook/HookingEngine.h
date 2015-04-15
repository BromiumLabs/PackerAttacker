#pragma once
#include <Windows.h>
#include <assert.h>
#include <functional>

#include "detours.h"


#define HOOK_DEFINE_2(reT, reTm, name, arg1, arg2) typedef reT (reTm *_orig ## name)(arg1, arg2); _orig ## name orig ## name; reT reTm on ## name(arg1, arg2); static reT reTm _on ## name(arg1, arg2);
#define HOOK_DEFINE_5(reT, reTm, name, arg1, arg2, arg3, arg4, arg5) typedef reT (reTm *_orig ## name)(arg1, arg2, arg3, arg4, arg5); _orig ## name orig ## name; reT reTm on ## name(arg1, arg2, arg3, arg4, arg5); static reT reTm _on ## name(arg1, arg2, arg3, arg4, arg5);
#define HOOK_DEFINE_8(reT, reTm, name, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) typedef reT (reTm *_orig ## name)(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8); _orig ## name orig ## name; reT reTm on ## name(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8); static reT reTm _on ## name(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
#define HOOK_DEFINE_10(reT, reTm, name, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10) typedef reT (reTm *_orig ## name)(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10); _orig ## name orig ## name; reT reTm on ## name(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10); static reT reTm _on ## name(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10);
#define HOOK_DEFINE_12(reT, reTm, name, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12) typedef reT (reTm *_orig ## name)(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12); _orig ## name orig ## name; reT reTm on ## name(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12); static reT reTm _on ## name(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12);

#define HOOK_GET_ORIG(object, library, name) object->orig ## name = (_orig ## name)GetProcAddress(LoadLibraryA(library), #name); assert(object->orig ## name);
#define HOOK_SET(object, hooks, name) hooks->placeHook(&(PVOID&)object->orig ## name, &_on ## name);


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