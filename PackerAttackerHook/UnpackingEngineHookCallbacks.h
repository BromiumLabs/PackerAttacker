#include "UnpackingEngine.h"


NTSTATUS WINAPI UnpackingEngine::_onNtProtectVirtualMemory(HANDLE process, PVOID* baseAddress, PULONG numberOfBytes, ULONG newProtection, PULONG OldProtection)
{
    auto sg = UnpackingEngine::getInstance()->lock->enterWithScopeGuard();
    return UnpackingEngine::getInstance()->onNtProtectVirtualMemory(process, baseAddress, numberOfBytes, newProtection, OldProtection);
}

NTSTATUS WINAPI UnpackingEngine::_onNtWriteVirtualMemory(HANDLE process, PVOID baseAddress, PVOID buffer, ULONG numberOfBytes, PULONG numberOfBytesWritten)
{
    auto sg = UnpackingEngine::getInstance()->lock->enterWithScopeGuard();
    return UnpackingEngine::getInstance()->onNtWriteVirtualMemory(process, baseAddress, buffer, numberOfBytes, numberOfBytesWritten);
}

BOOL WINAPI UnpackingEngine::_onCreateProcessInternalW(
        HANDLE hToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
        LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
        BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory,
        LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation, PHANDLE hNewToken)
{
    auto sg = UnpackingEngine::getInstance()->lock->enterWithScopeGuard();
    return UnpackingEngine::getInstance()->onCreateProcessInternalW(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
                                                                    bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo,
                                                                    lpProcessInformation, hNewToken);
}

NTSTATUS WINAPI UnpackingEngine::_onNtCreateThread(
        PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
        PCLIENT_ID ClientId, PCONTEXT ThreadContext, PINITIAL_TEB InitialTeb, BOOLEAN CreateSuspended)
{
    auto sg = UnpackingEngine::getInstance()->lock->enterWithScopeGuard();
    return UnpackingEngine::getInstance()->onNtCreateThread(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, ThreadContext, InitialTeb, CreateSuspended);
}

NTSTATUS WINAPI UnpackingEngine::_onNtMapViewOfSection(
        HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG ZeroBits, ULONG CommitSize,
        PLARGE_INTEGER SectionOffset, PULONG ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Protect)
{
    auto sg = UnpackingEngine::getInstance()->lock->enterWithScopeGuard();
    return UnpackingEngine::getInstance()->onNtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize,
                                                                SectionOffset, ViewSize, InheritDisposition, AllocationType, Protect);
}

NTSTATUS WINAPI UnpackingEngine::_onNtResumeThread(HANDLE thread, PULONG suspendCount)
{
    auto sg = UnpackingEngine::getInstance()->lock->enterWithScopeGuard();
    return UnpackingEngine::getInstance()->onNtResumeThread(thread, suspendCount);
}

long __stdcall UnpackingEngine::_onShallowException(PEXCEPTION_POINTERS info)
{
    return UnpackingEngine::getInstance()->onShallowException(info);
}

long __stdcall UnpackingEngine::_onDeepException(PEXCEPTION_POINTERS info)
{
    return UnpackingEngine::getInstance()->onDeepException(info);
}