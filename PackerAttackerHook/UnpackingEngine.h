#pragma once
#include "HookingEngine.h"
#include "TrackedMemoryBlock.h"
#include "SyncLock.h"
#include "ntdefs.h"

#include <Windows.h>
#include <map>


/* used to define a hook */
#define _HOOK_DEFINE_INTERNAL(reT, reTm, name, args, argnames) \
    typedef reT (reTm *_orig ## name) args; /* define the function prototype */ \
    _orig ## name orig ## name; /* create a pointer to the original function */ \
    __declspec(dllexport) reT reTm on ## name args; /* declare the member-fucntion that will be called internal to the class */ \
    __declspec(dllexport) static reT reTm _on ## name args /* declare the static function that acts as a hook callback and forwards the call into the member function */ \
    { \
        auto sg = getInstance()->lock->enterWithScopeGuard(); \
        if (getInstance()->shouldIgnoreHooks()) \
            return getInstance()->orig ## name argnames; \
        else \
            return getInstance()->on ## name argnames; \
    }

/* these are just "variadic" wrappers for the _HOOK_DEFINE_INTERNAL macro */
#define HOOK_DEFINE_1(reT, reTm, name, arg1) _HOOK_DEFINE_INTERNAL(reT, reTm, name, (arg1 a1), (a1));
#define HOOK_DEFINE_2(reT, reTm, name, arg1, arg2) _HOOK_DEFINE_INTERNAL(reT, reTm, name, (arg1 a1, arg2 a2), (a1, a2));
#define HOOK_DEFINE_3(reT, reTm, name, arg1, arg2, arg3) _HOOK_DEFINE_INTERNAL(reT, reTm, name, (arg1 a1, arg2 a2, arg3 a3), (a1, a2, a3));
#define HOOK_DEFINE_4(reT, reTm, name, arg1, arg2, arg3, arg4) _HOOK_DEFINE_INTERNAL(reT, reTm, name, (arg1 a1, arg2 a2, arg3 a3, arg4 a4), (a1, a2, a3, a4));
#define HOOK_DEFINE_5(reT, reTm, name, arg1, arg2, arg3, arg4, arg5) _HOOK_DEFINE_INTERNAL(reT, reTm, name, (arg1 a1, arg2 a2, arg3 a3, arg4 a4, arg5 a5), (a1, a2, a3, a4, a5));
#define HOOK_DEFINE_6(reT, reTm, name, arg1, arg2, arg3, arg4, arg5, arg6) _HOOK_DEFINE_INTERNAL(reT, reTm, name, (arg1 a1, arg2 a2, arg3 a3, arg4 a4, arg5 a5, arg6 a6), (a1, a2, a3, a4, a5, a6));
#define HOOK_DEFINE_7(reT, reTm, name, arg1, arg2, arg3, arg4, arg5, arg6, arg7) _HOOK_DEFINE_INTERNAL(reT, reTm, name, (arg1 a1, arg2 a2, arg3 a3, arg4 a4, arg5 a5, arg6 a6, arg7 a7), (a1, a2, a3, a4, a5, a6, a7));
#define HOOK_DEFINE_8(reT, reTm, name, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) _HOOK_DEFINE_INTERNAL(reT, reTm, name, (arg1 a1, arg2 a2, arg3 a3, arg4 a4, arg5 a5, arg6 a6, arg7 a7, arg8 a8), (a1, a2, a3, a4, a5, a6, a7, a8));
#define HOOK_DEFINE_10(reT, reTm, name, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10) _HOOK_DEFINE_INTERNAL(reT, reTm, name, (arg1 a1, arg2 a2, arg3 a3, arg4 a4, arg5 a5, arg6 a6, arg7 a7, arg8 a8, arg9 a9, arg10 a10), (a1, a2, a3, a4, a5, a6, a7, a8, a9, a10));
#define HOOK_DEFINE_12(reT, reTm, name, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12) _HOOK_DEFINE_INTERNAL(reT, reTm, name, (arg1 a1, arg2 a2, arg3 a3, arg4 a4, arg5 a5, arg6 a6, arg7 a7, arg8 a8, arg9 a9, arg10 a10, arg11 a11, arg12 a12), (a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12));

#define HOOK_GET_ORIG(object, library, name) object->orig ## name = (_orig ## name)GetProcAddress(LoadLibraryA(library), #name); assert(object->orig ## name);
#define HOOK_SET(object, hooks, name) hooks->placeHook(&(PVOID&)object->orig ## name, &_on ## name);


class UnpackingEngine
{
public:
    UnpackingEngine(void);
    ~UnpackingEngine(void);

    static UnpackingEngine* getInstance()
    {
        if (UnpackingEngine::instance == NULL)
            UnpackingEngine::instance = new UnpackingEngine();
        return UnpackingEngine::instance;
    }

    void initialize();
    void uninitialize();

private:
    static UnpackingEngine* instance;
    bool hooksReady, inAllocationHook, simulateDisabledDEP, bypassHooks;
    DWORD processID;
    HookingEngine* hooks;
    SyncLock* lock;

    std::vector<std::pair<DWORD, DWORD>> PESections;
    MemoryBlockTracker<TrackedMemoryBlock> writeablePEBlocks;
    MemoryBlockTracker<TrackedMemoryBlock> executableBlocks;
    MemoryBlockTracker<TrackedMemoryBlock> blacklistedBlocks;
    std::map<DWORD, MemoryBlockTracker<TrackedCopiedMemoryBlock>> remoteMemoryBlocks;
    std::map<DWORD, DWORD> suspendedThreads;

    void ignoreHooks(bool should) { this->bypassHooks = should; }
    bool shouldIgnoreHooks() { return this->bypassHooks; }
    void startTrackingPEMemoryBlocks();
    bool isPEMemory(DWORD address);
    void startTrackingRemoteMemoryBlock(DWORD pid, DWORD baseAddress, DWORD size, unsigned char* data);
    void dumpRemoteMemoryBlocks();
    void dumpMemoryBlock(TrackedMemoryBlock block, DWORD ep);
    void dumpMemoryBlock(char* fileName, DWORD size, const unsigned char* data);
    bool isSelfProcess(HANDLE process);
    DWORD getProcessIdIfRemote(HANDLE process);
    ULONG processMemoryBlockFromHook(const char* source, DWORD address, DWORD size, ULONG newProtection, ULONG oldProtection, bool considerOldProtection);

    /* NtProtectVirtualMemory hook */
    HOOK_DEFINE_5(NTSTATUS, NTAPI, NtProtectVirtualMemory, HANDLE, PVOID*, PULONG, ULONG, PULONG);
    /* NtWriteVirtualMemory hook */
    HOOK_DEFINE_5(NTSTATUS, NTAPI, NtWriteVirtualMemory, HANDLE, PVOID, PVOID, ULONG, PULONG);
    /* NtCreateThread hook */
    HOOK_DEFINE_8(NTSTATUS, NTAPI, NtCreateThread, 
                PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE,
                PCLIENT_ID, PCONTEXT, PINITIAL_TEB, BOOLEAN);
    /* NtMapViewOfSection hook */
    HOOK_DEFINE_10(NTSTATUS, NTAPI, NtMapViewOfSection,
                HANDLE, HANDLE, PVOID*, ULONG, ULONG, PLARGE_INTEGER,
                OUT PULONG, SECTION_INHERIT, ULONG,  ULONG);
    /* NtResumeThread hook */
    HOOK_DEFINE_2(NTSTATUS, NTAPI, NtResumeThread, HANDLE, PULONG);
    /* CreateProcessInternal hook */
    HOOK_DEFINE_12(BOOL, WINAPI, CreateProcessInternalW,
                HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
                LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR,
                LPSTARTUPINFOW, LPPROCESS_INFORMATION, PHANDLE);
    /* NtDelayExecution hook */
    HOOK_DEFINE_2(NTSTATUS, NTAPI, NtDelayExecution, BOOLEAN, PLARGE_INTEGER);
    /* NtAllocateVirtualMemory hook */
    HOOK_DEFINE_6(NTSTATUS, NTAPI, NtAllocateVirtualMemory, HANDLE, PVOID*, ULONG, PULONG, ULONG, ULONG);


	HOOK_DEFINE_6(NTSTATUS, NTAPI, RtlDecompressBuffer, USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG);

    /* exception handler for hooking execution on tracked pages */
    long onShallowException(PEXCEPTION_POINTERS info);
    static long __stdcall _onShallowException(PEXCEPTION_POINTERS info)
    {
        return UnpackingEngine::getInstance()->onShallowException(info);
    }

    /* exception handler for detecting crashes */
    long onDeepException(PEXCEPTION_POINTERS info);
    static long __stdcall _onDeepException(PEXCEPTION_POINTERS info)
    {
        return UnpackingEngine::getInstance()->onDeepException(info);
    }

};

