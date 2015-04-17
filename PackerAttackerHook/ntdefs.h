#pragma once
#include <Windows.h>

#define IS_EXECUTABLE_PROT(x) (x >= PAGE_EXECUTE && x <= PAGE_EXECUTE_WRITECOPY)
#define IS_WRITEABLE_PROT(x) (x == PAGE_EXECUTE_READWRITE || x == PAGE_READWRITE)
#define REMOVE_EXECUTABLE_PROT(x) (x / PAGE_EXECUTE)
#define REMOVE_WRITEABLE_PROT(x) (x / PAGE_READONLY)

#define CHARACTERISTIC_CODE 0x00000020
#define CHARACTERISTIC_INIT 0x00000040
#define CHARACTERISTIC_UN_INIT 0x00000080
#define CHARACTERISTIC_NO_MAP 0x00000800
#define CHARACTERISTIC_DISCARD 0x02000000
#define CHARACTERISTIC_EXECUTABLE 0x20000000
#define CHARACTERISTIC_WRITEABLE 0x80000000
#define CHECK_FLAG(a, b) ((a & b) == b)

typedef enum _SECTION_INHERIT
{
    ViewShare=1,
    ViewUnmap=2
} SECTION_INHERIT, *PSECTION_INHERIT;

typedef struct _LSA_UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID
{
    PVOID UniqueProcess;
    PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _INITIAL_TEB
{
    PVOID StackBase;
    PVOID StackLimit;
    PVOID StackCommit;
    PVOID StackCommitMax;
    PVOID StackReserved;
} INITIAL_TEB, *PINITIAL_TEB;

/*typedef NTSTATUS (WINAPI *_NtQueryInformationThread)(HANDLE, LONG, PVOID, ULONG, PULONG);

typedef enum _THREAD_INFORMATION_CLASS
{
    ThreadBasicInformation,
    ThreadTimes,
    ThreadPriority,
    ThreadBasePriority,
    ThreadAffinityMask,
    ThreadImpersonationToken,
    ThreadDescriptorTableEntry,
    ThreadEnableAlignmentFaultFixup,
    ThreadEventPair,
    ThreadQuerySetWin32StartAddress,
    ThreadZeroTlsCell,
    ThreadPerformanceCount,
    ThreadAmILastThread,
    ThreadIdealProcessor,
    ThreadPriorityBoost,
    ThreadSetTlsArrayAddress,
    ThreadIsIoPending,
    ThreadHideFromDebugger
} THREAD_INFORMATION_CLASS, *PTHREAD_INFORMATION_CLASS;

typedef LONG KPRIORITY;
typedef struct _THREAD_BASIC_INFORMATION {
  NTSTATUS                ExitStatus;
  PVOID                   TebBaseAddress;
  CLIENT_ID               ClientId;
  KAFFINITY               AffinityMask;
  KPRIORITY               Priority;
  KPRIORITY               BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

DWORD _GetThreadId(HANDLE thread, HANDLE process)
{
    auto NtQueryInformationThread = (_NtQueryInformationThread)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationThread");

    THREAD_BASIC_INFORMATION threadInformation; 
    if (NtQueryInformationThread(thread, ThreadBasicInformation, &threadInformation, sizeof(DWORD), NULL) == 0)
    {
        if (threadInformation.TebBaseAddress != 0)
        {
            LPVOID threadIDAddress = (LPVOID((DWORD)threadInformation.TebBaseAddress + 0x24));
            DWORD threadID;
            if (!ReadProcessMemory(process, threadIDAddress, &threadID, 4, NULL))
                return -2;

            return threadID;
        }
        else
            return -1;
    }
    else
        return 0;
}*/