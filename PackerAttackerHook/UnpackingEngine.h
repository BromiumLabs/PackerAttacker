#pragma once
#include "HookingEngine.h"
#include "TrackedMemoryBlock.h"
#include "SyncLock.h"
#include "ntdefs.h"

#include <Windows.h>
#include <map>


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
    bool hooksReady;
    DWORD processID;
    HookingEngine* hooks;
    SyncLock* lock;

    MemoryBlockTracker<TrackedMemoryBlock> writeablePEBlocks;
    MemoryBlockTracker<TrackedMemoryBlock> executableBlocks;
    MemoryBlockTracker<TrackedMemoryBlock> blacklistedBlocks;
    std::map<DWORD, MemoryBlockTracker<TrackedCopiedMemoryBlock>> remoteMemoryBlocks;
    std::map<DWORD, DWORD> suspendedThreads;

    void startTrackingPEMemoryBlocks();
    void startTrackingRemoteMemoryBlock(DWORD pid, DWORD baseAddress, DWORD size, unsigned char* data);
    void dumpRemoteMemoryBlocks();
    void dumpMemoryBlock(TrackedMemoryBlock block, DWORD ep);
    void dumpMemoryBlock(char* fileName, DWORD size, const unsigned char* data);
    DWORD getProcessIdIfRemote(HANDLE process);

    /* NtProtectVirtualMemory hook */
    HOOK_DEFINE_5(NTSTATUS, WINAPI, NtProtectVirtualMemory, HANDLE, PVOID*, PULONG, ULONG, PULONG);
    /* NtWriteVirtualMemory hook */
    HOOK_DEFINE_5(NTSTATUS, WINAPI, NtWriteVirtualMemory, HANDLE, PVOID, PVOID, ULONG, PULONG);
    /* NtCreateThread hook */
    HOOK_DEFINE_8(NTSTATUS, WINAPI, NtCreateThread, 
                PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE,
                PCLIENT_ID, PCONTEXT, PINITIAL_TEB, BOOLEAN);
    /* NtMapViewOfSection hook */
    HOOK_DEFINE_10(NTSTATUS, WINAPI, NtMapViewOfSection,
                HANDLE, HANDLE, PVOID*, ULONG, ULONG, PLARGE_INTEGER,
                OUT PULONG, SECTION_INHERIT, ULONG,  ULONG);
    /* NtResumeThread hook */
    HOOK_DEFINE_2(NTSTATUS, WINAPI, NtResumeThread, HANDLE, PULONG);
    /* CreateProcessInternal hook */
    HOOK_DEFINE_12(BOOL, WINAPI, CreateProcessInternalW,
                HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
                LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR,
                LPSTARTUPINFOW, LPPROCESS_INFORMATION, PHANDLE);

    /* exception handler for hooking execution on tracked pages */
    long onShallowException(PEXCEPTION_POINTERS info);
    static long __stdcall _onShallowException(PEXCEPTION_POINTERS info);

    /* exception handler for detecting crashes */
    long onDeepException(PEXCEPTION_POINTERS info);
    static long __stdcall _onDeepException(PEXCEPTION_POINTERS info);

};

