#include "UnpackingEngine.h"
#include "UnpackingEngineHookCallbacks.h"
#include "Memory.h"
#include "Logger.h"

#include <fstream>
#include <sstream>
#include <assert.h>

UnpackingEngine* UnpackingEngine::instance = NULL;

UnpackingEngine::UnpackingEngine(void)
{
    this->hooks = new HookingEngine();
    this->lock = new SyncLock();
    this->hooksReady = false;
    this->inAllocationHook = false;
}


UnpackingEngine::~UnpackingEngine(void)
{
    delete this->hooks;
    delete this->lock;
}

void UnpackingEngine::initialize()
{
    auto sg = this->lock->enterWithScopeGuard();

    this->processID = GetCurrentProcessId();

    /* init logger */
    char logName[MAX_PATH];
    sprintf_s<MAX_PATH>(logName, "C:\\dumps\\[%d]_packer_attacker.log", this->processID);
    Logger::getInstance()->initialize(logName);

    Logger::getInstance()->write("Starting hooking process...");

    /* get the current DEP state, then make sure DEP is on */
    DWORD depFlags;
    BOOL depCantChange;
    GetProcessDEPPolicy(GetCurrentProcess(), &depFlags, &depCantChange);
    this->simulateDisabledDEP = (depFlags & PROCESS_DEP_ENABLE) != PROCESS_DEP_ENABLE;

    if (this->simulateDisabledDEP && depCantChange)
         Logger::getInstance()->write("ERROR: Cannot enable DEP for this process!");
    else
        SetProcessDEPPolicy(PROCESS_DEP_ENABLE);

    /* place hooks and track PE section */
    HOOK_GET_ORIG(this, "ntdll.dll", NtProtectVirtualMemory);
    HOOK_GET_ORIG(this, "ntdll.dll", NtWriteVirtualMemory);
    HOOK_GET_ORIG(this, "ntdll.dll", NtCreateThread);
    HOOK_GET_ORIG(this, "ntdll.dll", NtMapViewOfSection);
    HOOK_GET_ORIG(this, "ntdll.dll", NtResumeThread);
    HOOK_GET_ORIG(this, "ntdll.dll", NtDelayExecution);
    HOOK_GET_ORIG(this, "ntdll.dll", NtAllocateVirtualMemory);
    HOOK_GET_ORIG(this, "Kernel32.dll", CreateProcessInternalW);

    Logger::getInstance()->write("Finding original function addresses... DONE");

    this->startTrackingPEMemoryBlocks();

    Logger::getInstance()->write("Tracking PE memory blocks... DONE");

    this->hooks->doTransaction([=](){
        this->hooks->placeShallowExceptionHandlerHook(&UnpackingEngine::_onShallowException);
        this->hooks->placeDeepExceptionHandlerHook(&UnpackingEngine::_onDeepException);
        HOOK_SET(this, this->hooks, NtProtectVirtualMemory);
        HOOK_SET(this, this->hooks, NtWriteVirtualMemory);
        HOOK_SET(this, this->hooks, NtCreateThread);
        HOOK_SET(this, this->hooks, NtMapViewOfSection);
        HOOK_SET(this, this->hooks, NtResumeThread);
        HOOK_SET(this, this->hooks, NtDelayExecution);
        HOOK_SET(this, this->hooks, NtAllocateVirtualMemory);
        HOOK_SET(this, this->hooks, CreateProcessInternalW);
    });

    Logger::getInstance()->write("Placing hooks... DONE");
    Logger::getInstance()->write("Hooks ready!");

    hooksReady = true;
}

void UnpackingEngine::uninitialize()
{
    auto sg = this->lock->enterWithScopeGuard();

    this->dumpRemoteMemoryBlocks();
    Logger::getInstance()->uninitialize();
}

void UnpackingEngine::startTrackingPEMemoryBlocks()
{
    auto mainModule = (BYTE*)GetModuleHandle(NULL);
    assert(mainModule);

    auto dosHeader = MakePointer<IMAGE_DOS_HEADER*, BYTE*>(mainModule, 0);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return;

    auto ntHeaders = MakePointer<IMAGE_NT_HEADERS*, BYTE*>(mainModule, dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
        return;

    auto baseOfCode = MakePointer<DWORD, HMODULE>((HMODULE)mainModule, ntHeaders->OptionalHeader.BaseOfCode);
    auto baseOfData = MakePointer<DWORD, HMODULE>((HMODULE)mainModule, ntHeaders->OptionalHeader.BaseOfData);
    auto entryPoint = MakePointer<DWORD, HMODULE>((HMODULE)mainModule, ntHeaders->OptionalHeader.AddressOfEntryPoint);

    Logger::getInstance()->write("PE HEADER SAYS\n\tCode: 0x%0x\n\tData: 0x%0x\n\tEP: 0x%0x", baseOfCode, baseOfData, entryPoint);
 

    bool eipAlreadyIgnored = false;
    auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (DWORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, sectionHeader++)
    {
        DWORD destination = MakePointer<DWORD, HMODULE>((HMODULE)mainModule, sectionHeader->VirtualAddress);
        DWORD size = sectionHeader->SizeOfRawData;
        if (size <= 0)
        {
            auto nextSection = sectionHeader; nextSection++;
            size = nextSection->VirtualAddress - sectionHeader->VirtualAddress;
        }

        PESections.push_back(std::make_pair(destination, destination + size));

        if (!CHECK_FLAG(sectionHeader->Characteristics, CHARACTERISTIC_WRITEABLE))
            continue; /* skip un-writeable sections */

        if (!CHECK_FLAG(sectionHeader->Characteristics, CHARACTERISTIC_EXECUTABLE))
            continue; /* skip non-executable sections */


        ULONG oldProtection;
        auto ret = this->origNtProtectVirtualMemory(GetCurrentProcess(), (PVOID*)&destination, (PULONG)&size, PAGE_EXECUTE_READ, &oldProtection);
        if (ret != 0)
        {
            Logger::getInstance()->write("Failed to remove execution rights from %s at 0x%08x (char: 0x%08x). GetLastError() == %d |  RET == 0x%08x", sectionHeader->Name, destination, sectionHeader->Characteristics, GetLastError(), ret);
            continue; /* failed to remove write privs ;( */
        }

        this->writeablePEBlocks.startTracking(destination, size, oldProtection);

        Logger::getInstance()->write("Placed hook on PE section %s at 0x%08x to 0x%08x (char: 0x%08x)", sectionHeader->Name, destination, destination+size, sectionHeader->Characteristics);
    }

}

bool UnpackingEngine::isPEMemory(DWORD address)
{
    for (unsigned int i = 0; i < this->PESections.size(); i++)
        if (address >= this->PESections[i].first && address <= this->PESections[i].second)
            return true;
    return false;
}

void UnpackingEngine::startTrackingRemoteMemoryBlock(DWORD pid, DWORD baseAddress, DWORD size, unsigned char* data)
{
    if (this->remoteMemoryBlocks.find(pid) == this->remoteMemoryBlocks.end())
        this->remoteMemoryBlocks[pid] = MemoryBlockTracker<TrackedCopiedMemoryBlock>();

    TrackedCopiedMemoryBlock add(baseAddress, size, data);
    this->remoteMemoryBlocks[pid].startTracking(add);
}

void UnpackingEngine::dumpRemoteMemoryBlocks()
{
    for (auto mIT = this->remoteMemoryBlocks.begin(); mIT != this->remoteMemoryBlocks.end(); mIT++)
    {
        auto PID = mIT->first;
        auto blocks = mIT->second;
        for (auto IT = blocks.trackedMemoryBlocks.begin(); IT != blocks.trackedMemoryBlocks.end(); IT++)
        {
            if (IT->size < 50)
                continue;

            char fileName[MAX_PATH];
            sprintf(fileName, "C:\\dumps\\[%d]_%d_0x%08x_to_0x%08x.WPM.DMP", PID, GetTickCount(), IT->startAddress, IT->endAddress);
            this->dumpMemoryBlock(fileName, IT->buffer.size(), (const unsigned char*)IT->buffer.data());
        }
    }
}

void UnpackingEngine::dumpMemoryBlock(TrackedMemoryBlock block, DWORD ep)
{
    char fileName[MAX_PATH];
    sprintf(fileName, "C:\\dumps\\[%d]_%d_0x%08x_to_0x%08x_EP_0x%08x_IDX_%d.DMP", this->processID, GetTickCount(), block.startAddress, block.endAddress, ep, ep - block.startAddress);

    this->dumpMemoryBlock(fileName, block.size, (const unsigned char*)block.startAddress);
}

void UnpackingEngine::dumpMemoryBlock(char* fileName, DWORD size, const unsigned char* data)
{
    std::fstream file(fileName, std::ios::out | std::ios::binary);
    if (file.is_open())
    {
        for (int i = 0; i < size; i++)
            file.write((const char*)&data[i], 1);
        file.close();
    }
    else
        Logger::getInstance()->write("Failed to create dump file with name '%s'!", fileName);
}

bool UnpackingEngine::isSelfProcess(HANDLE process)
{
    return (process == 0 || process == INVALID_HANDLE_VALUE || GetProcessId(process) == this->processID);
}

DWORD UnpackingEngine::getProcessIdIfRemote(HANDLE process)
{
     if (process == 0 && process == INVALID_HANDLE_VALUE)
         return 0;
     
     DWORD pid = GetProcessId(process);
     return (pid == this->processID) ? 0 : pid;
}

ULONG UnpackingEngine::processMemoryBlockFromHook(const char* source, DWORD address, DWORD size, ULONG newProtection, ULONG oldProtection, bool considerOldProtection)
{
    PVOID _address = (PVOID)address;
    DWORD _size = size;
    ULONG _oldProtection = oldProtection;

    auto it = this->writeablePEBlocks.findTracked(address, size);
    if (it != this->writeablePEBlocks.nullMarker())
    {
        /* this is a PE section that we're currently tracking, let's make sure it stays that way */
        if (IS_WRITEABLE_PROT(newProtection))
        {
            this->origNtProtectVirtualMemory(GetCurrentProcess(), &_address, &_size, REMOVE_WRITEABLE_PROT(newProtection), &_oldProtection);
            Logger::getInstance()->write("[%s] Persisting hook on PE section at 0x%08x - 0x%08x", source, address, address + size);
        }
        else
            Logger::getInstance()->write("[%s] Block detected as writeable PE block, no need to persist hook 0x%08x - 0x%08x", source, address, address + size);
    }
    else if (considerOldProtection && 
            IS_WRITEABLE_PROT(newProtection) &&
            !IS_WRITEABLE_PROT(oldProtection) &&
            this->isPEMemory(address)) // newly writeable pe section
    {
        /* this is a PE section being set to writeable, track it */
        this->origNtProtectVirtualMemory(GetCurrentProcess(), &_address, &_size, REMOVE_WRITEABLE_PROT(newProtection), &_oldProtection);
        this->writeablePEBlocks.startTracking(address, size, newProtection);
        Logger::getInstance()->write("[%s] Placed write hook on PE section at 0x%08x - 0x%08x", source, address, address + size);
    }
    else if (IS_EXECUTABLE_PROT(newProtection))
    {
        /* page was set to executable, track the page and remove executable rights */
        if (!this->blacklistedBlocks.isTracked(address, size))
        {
            this->executableBlocks.startTracking(address, size, (DWORD)newProtection);
            this->origNtProtectVirtualMemory(GetCurrentProcess(), &_address, &_size, REMOVE_EXECUTABLE_PROT(newProtection), &_oldProtection);
            Logger::getInstance()->write("[%s] Placed execution hook on 0x%08x - 0x%08x", source, address, address + size);
        }
        else
            Logger::getInstance()->write("[%s] Failed to place execution hook on BLACKLISTED BLOCK 0x%08x - 0x%08x", source, address, address + size);
    }
    else
    {
        auto it = this->executableBlocks.findTracked(address, size);
        if (it == this->executableBlocks.nullMarker())
            Logger::getInstance()->write("[%s] No need to hook block 0x%08x - 0x%08x", source, address, address + size);
    }

    return _oldProtection;
}

NTSTATUS UnpackingEngine::onNtProtectVirtualMemory(HANDLE process, PVOID* baseAddress, PULONG numberOfBytes, ULONG newProtection, PULONG OldProtection)
{
    /* do original protection */
    ULONG _oldProtection;
    auto ret = this->origNtProtectVirtualMemory(process, baseAddress, numberOfBytes, newProtection, &_oldProtection);

    if (OldProtection)
        *OldProtection = _oldProtection;

    /* we do not want to re-process this if we did in NtAllocate hook, as it sometimes calls NtProtect */
    if (this->inAllocationHook)
        return ret;

    if (ret == 0 && this->hooksReady)
        Logger::getInstance()->write("NtProtectVirtualMemory(TargetPID %d, 0x%08x, 0x%08x, 0x%08x, 0x%08x)\n", GetProcessId(process), (DWORD)*baseAddress, (DWORD)*numberOfBytes, newProtection, OldProtection);

    if (ret == 0 && this->hooksReady && this->isSelfProcess(process))
    {
        _oldProtection = this->processMemoryBlockFromHook("onNtProtectVirtualMemory", (DWORD)*baseAddress, (DWORD)*numberOfBytes, newProtection, *OldProtection, true);
        if (OldProtection)
            *OldProtection = _oldProtection;
    }

    return ret;
}

NTSTATUS UnpackingEngine::onNtWriteVirtualMemory(HANDLE process, PVOID baseAddress, PVOID buffer, ULONG numberOfBytes, PULONG numberOfBytesWritten)
{
    if (this->hooksReady)
        Logger::getInstance()->write("PRE-NtWriteVirtualMemory(TargetPID %d, Address 0x%08x, Count 0x%08x)\n", GetProcessId(process), baseAddress, numberOfBytes);

    auto ret = this->origNtWriteVirtualMemory(process, baseAddress, buffer, numberOfBytes, numberOfBytesWritten);

    if (this->hooksReady)
        Logger::getInstance()->write("PST-NtWriteVirtualMemory(TargetPID %d, Address 0x%08x, Count 0x%08x) RET: 0x%08x\n", GetProcessId(process), baseAddress, (numberOfBytesWritten) ? *numberOfBytesWritten : numberOfBytes, ret);

    if (ret == 0 && this->hooksReady)
    {
        DWORD targetPID = this->getProcessIdIfRemote(process);
        if (targetPID)
            this->startTrackingRemoteMemoryBlock(targetPID, (DWORD)baseAddress, (DWORD)numberOfBytes, (unsigned char*)buffer);
    }

    return ret;
}

BOOL WINAPI UnpackingEngine::onCreateProcessInternalW(
    HANDLE hToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation, PHANDLE hNewToken)
{
    auto ret = origCreateProcessInternalW(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
        bInheritHandles, dwCreationFlags | CREATE_SUSPENDED, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, hNewToken);

    if ((dwCreationFlags & CREATE_SUSPENDED) != CREATE_SUSPENDED)
    {
        /* the process wasnt initially suspended, so we can inject right away */
        Logger::getInstance()->write("Propogating into process %d from CreateProcessInternalW() hook.\n", lpProcessInformation->dwProcessId);
        hooks->injectIntoProcess(lpProcessInformation->hProcess, L"PackerAttackerHook.dll");
        Logger::getInstance()->write("Propogation into process %d from CreateProcessInternalW() hook COMPLETE!\n", lpProcessInformation->dwProcessId);

        if (ResumeThread(lpProcessInformation->hThread) == -1)
            Logger::getInstance()->write("Failed to resume process! Thread %d\n", lpProcessInformation->dwThreadId);
    }
    else
    {
        /* the process was created as suspended, track the thread and only inject once it is resumed */
        this->suspendedThreads[lpProcessInformation->dwThreadId] = lpProcessInformation->dwProcessId;
    }

    return ret;
}

NTSTATUS WINAPI UnpackingEngine::onNtCreateThread(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
    PCLIENT_ID ClientId, PCONTEXT ThreadContext, PINITIAL_TEB InitialTeb, BOOLEAN CreateSuspended)
{
    if (this->hooksReady)
        Logger::getInstance()->write("NtCreateThread(TargetPID %d, Entry 0x%08x)\n", GetProcessId(ProcessHandle), ThreadContext->Eip);

    if (this->hooksReady)
    {
        if (this->isSelfProcess(ProcessHandle))
        {
            /* the thread is in this process, check if it is starting on a tracked executable block */
            auto it = this->executableBlocks.findTracked(ThreadContext->Eip, 1);
            if (it != this->executableBlocks.nullMarker())
            {
                /* it's an executable block being tracked */
                /* set the block back to executable */
                ULONG _oldProtection;
                auto ret = this->origNtProtectVirtualMemory(GetCurrentProcess(), (PVOID*)&it->startAddress, (PULONG)&it->size, (DWORD)it->neededProtection, &_oldProtection);
                if (ret == 0)
                {
                    /* dump the motherfucker and stop tracking it */
                    this->blacklistedBlocks.startTracking(*it);
                    this->dumpMemoryBlock(*it, ThreadContext->Eip);
                    this->executableBlocks.stopTracking(it);
                }
            }
        }
    }

    return this->origNtCreateThread(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, ThreadContext, InitialTeb, CreateSuspended);
}

NTSTATUS WINAPI UnpackingEngine::onNtMapViewOfSection(
    HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG ZeroBits, ULONG CommitSize,
    PLARGE_INTEGER SectionOffset, PULONG ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Protect)
{
    if (this->hooksReady)
        Logger::getInstance()->write("PRE-NtMapViewOfSection(TargetPID %d, Address 0x%08x, Size 0x%08x)\n", GetProcessId(ProcessHandle), (DWORD)*BaseAddress, (DWORD)*ViewSize);

    auto ret = this->origNtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize,
                                            SectionOffset, ViewSize, InheritDisposition, AllocationType, Protect);

    if (this->hooksReady)
        Logger::getInstance()->write("PST-NtMapViewOfSection(TargetPID %d, Address is 0x%08x, Size 0x%08x) RET: 0x%08x\n", GetProcessId(ProcessHandle), (DWORD)*BaseAddress, (DWORD)*ViewSize, ret);

    if (ret == 0 && this->hooksReady)
    {
        DWORD targetPID = this->getProcessIdIfRemote(ProcessHandle);
        if (targetPID)
        {
            //TODO: clean this up, there's no reason we have to allocate a buffer and use an RPM() call.
            DWORD bytesRead;
            unsigned char* buffer = new unsigned char[(DWORD)*ViewSize];
            if (ReadProcessMemory(ProcessHandle, *BaseAddress, &buffer[0], (DWORD)*ViewSize, &bytesRead) && bytesRead > 0)
            {
                char fileName[MAX_PATH];
                sprintf(fileName, "C:\\dumps\\[%d]_%d_0x%08x_to_0x%08x.MVOS.DMP", targetPID, GetTickCount(), (DWORD)*BaseAddress, (DWORD)*BaseAddress + (DWORD)*ViewSize);

                this->dumpMemoryBlock(fileName, bytesRead, (const unsigned char*)buffer);
            }
            else
                Logger::getInstance()->write("Failed to ReadProcessMemory() from NtMapViewOfSection() hook! (Address is 0x%08x, Size is 0x%08x) (PID is %d)\n", (DWORD)*BaseAddress, (DWORD)*ViewSize, GetProcessId(ProcessHandle));

            delete [] buffer;
        }
    }

    return ret;
}

NTSTATUS WINAPI UnpackingEngine::onNtResumeThread(HANDLE thread, PULONG suspendCount)
{
    auto threadId = GetThreadId(thread);
    if (this->suspendedThreads.find(threadId) != this->suspendedThreads.end())
    {
        auto targetPID = suspendedThreads[threadId];
        Logger::getInstance()->write("Propogating into process %d from NtResumeThread() hook.\n", targetPID);

        auto targetHandle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, FALSE, targetPID);
        if (targetHandle == INVALID_HANDLE_VALUE)
            Logger::getInstance()->write("FAILED to open process %d from NtResumeThread() hook!\n", targetPID);
        else
        {
            hooks->injectIntoProcess(targetHandle, L"PackerAttackerHook.dll");
            Logger::getInstance()->write("Propogation into process %d from NtResumeThread() hook COMPLETE!\n", targetPID);
        }

    }

    return this->origNtResumeThread(thread, suspendCount);
}

NTSTATUS WINAPI UnpackingEngine::onNtDelayExecution(BOOLEAN alertable, PLARGE_INTEGER time)
{
    Logger::getInstance()->write("Sleep call detected (Low part: %d, High part: %d).", time->LowPart, time->HighPart);

    return this->origNtDelayExecution(alertable, time);
}

NTSTATUS WINAPI UnpackingEngine::onNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG ZeroBits, PULONG RegionSize, ULONG AllocationType, ULONG Protect)
{
    if (this->inAllocationHook)
        return this->origNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);

    this->inAllocationHook = true;
        if (this->hooksReady)
            Logger::getInstance()->write("PRE-NtAllocateVirtualMemory(TargetPID %d, Address 0x%08x, Size 0x%08x, Protection 0x%08x)\n", GetProcessId(ProcessHandle), (DWORD)*BaseAddress, (DWORD)*RegionSize, Protect);

        auto ret = this->origNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);

        if (this->hooksReady)
            Logger::getInstance()->write("PST-NtAllocateVirtualMemory(TargetPID %d, Address 0x%08x, Count 0x%08x, Protection 0x%08x) RET: 0x%08x\n", GetProcessId(ProcessHandle), (DWORD)*BaseAddress, (RegionSize) ? *RegionSize : 0, Protect, ret);


        if (ret == 0 && this->hooksReady && this->isSelfProcess(ProcessHandle))
            this->processMemoryBlockFromHook("onNtAllocateVirtualMemory", (DWORD)*BaseAddress, (DWORD)*RegionSize, Protect, NULL, false);
    this->inAllocationHook = false;

    return ret;
}

long UnpackingEngine::onShallowException(PEXCEPTION_POINTERS info)
{
    // ref: https://msdn.microsoft.com/en-us/library/windows/desktop/aa363082(v=vs.85).aspx
    if (info->ExceptionRecord->ExceptionCode != STATUS_ACCESS_VIOLATION)
        return EXCEPTION_CONTINUE_SEARCH; /* only worried about access violations */

    if (info->ExceptionRecord->NumberParameters != 2)
        return EXCEPTION_CONTINUE_SEARCH; /* should have 2 params */

    bool isWriteException = (info->ExceptionRecord->ExceptionInformation[0] != 8);
    DWORD exceptionAddress = info->ExceptionRecord->ExceptionInformation[1];//(DWORD)info->ExceptionRecord->ExceptionAddress;

    if (isWriteException) /* monitor writes to tracked PE sections */
    {
        auto sg = this->lock->enterWithScopeGuard();

        auto it = this->writeablePEBlocks.findTracked(exceptionAddress, 1);
        if (it == this->writeablePEBlocks.nullMarker())
        {
            Logger::getInstance()->write("STATUS_ACCESS_VIOLATION write on 0x%08x not treated as hook!", exceptionAddress);
            return EXCEPTION_CONTINUE_SEARCH; /* we're not tracking the page */
        }

        /* it's a PE section beign tracked */
        /* set the section back to writeable */
        ULONG _oldProtection;
        auto ret = this->origNtProtectVirtualMemory(GetCurrentProcess(), (PVOID*)&it->startAddress, (PULONG)&it->size, PAGE_READWRITE, &_oldProtection);
        if (ret != 0)
        {
            Logger::getInstance()->write("Failed to removed write hook on 0x%08x!", exceptionAddress);
            return EXCEPTION_CONTINUE_SEARCH; /* couldn't set page back to regular protection, wtf? */
        }

        /* start tracking execution in the section and stop tracking writes */
        this->executableBlocks.startTracking(*it);
        this->writeablePEBlocks.stopTracking(it);

        Logger::getInstance()->write("STATUS_ACCESS_VIOLATION write on 0x%08x triggered write hook!", exceptionAddress);

        /* writing to the section should work now */
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    else /* monitor executes to tracked executable blocks */
    {
        auto sg = this->lock->enterWithScopeGuard();

        auto it = this->executableBlocks.findTracked(exceptionAddress, 1);
        if (it == this->executableBlocks.nullMarker())
        {
            /* this isn't memory we've hooked, so this is an unrelated DEP exception.
            If the process didn't initially have DEP enabled, we should fix the protection so it can execute.
            If the process did initially have DEP enabled, we should let it crash as normal */
            if (this->simulateDisabledDEP)
            {
                ULONG _oldProtection;
                DWORD _address = exceptionAddress;
                ULONG _size = 1;
                auto ret = this->origNtProtectVirtualMemory(GetCurrentProcess(), (PVOID*)&_address, (PULONG)&_size, PAGE_EXECUTE_READWRITE, &_oldProtection);
                Logger::getInstance()->write("STATUS_ACCESS_VIOLATION execute on 0x%08x (NOT A HOOK). Simulating DEP-lessness from 0x%08x to 0x%08x.", exceptionAddress, _address, _address + _size);

                return EXCEPTION_CONTINUE_EXECUTION;
            }
            else
            {
                Logger::getInstance()->write("STATUS_ACCESS_VIOLATION execute on 0x%08x (NOT A HOOK). No need to simulate DEP-lessness.", exceptionAddress);
                return EXCEPTION_CONTINUE_SEARCH;
            }
        }

        /* it's an executable block being tracked */
        /* set the block back to executable */
        ULONG _oldProtection;
        auto ret = this->origNtProtectVirtualMemory(GetCurrentProcess(), (PVOID*)&it->startAddress, (PULONG)&it->size, (DWORD)it->neededProtection, &_oldProtection);
        if (ret != 0)
        {
            Logger::getInstance()->write("Failed to removed execute hook on 0x%08x!", exceptionAddress);
            return EXCEPTION_CONTINUE_SEARCH; /* couldn't set page back to executable, wtf? */
        }

        /* dump the motherfucker and stop tracking it */
        this->blacklistedBlocks.startTracking(*it);
        this->dumpMemoryBlock(*it, exceptionAddress);
        this->executableBlocks.stopTracking(it);

        Logger::getInstance()->write("STATUS_ACCESS_VIOLATION execute on 0x%08x triggered execute hook!", exceptionAddress);

        /* execution should work now */
        return EXCEPTION_CONTINUE_EXECUTION;
    }
}


long UnpackingEngine::onDeepException(PEXCEPTION_POINTERS info)
{
    const char* exceptionDesc = "unknown";
    if (info->ExceptionRecord->ExceptionCode == STATUS_WAIT_0) exceptionDesc = "STATUS_WAIT_0";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_ABANDONED_WAIT_0) exceptionDesc = "STATUS_ABANDONED_WAIT_0";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_USER_APC) exceptionDesc = "STATUS_USER_APC";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_TIMEOUT) exceptionDesc = "STATUS_TIMEOUT";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_PENDING) exceptionDesc = "STATUS_PENDING";
    else if (info->ExceptionRecord->ExceptionCode == DBG_EXCEPTION_HANDLED) exceptionDesc = "DBG_EXCEPTION_HANDLED";
    else if (info->ExceptionRecord->ExceptionCode == DBG_CONTINUE) exceptionDesc = "DBG_CONTINUE";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_SEGMENT_NOTIFICATION) exceptionDesc = "STATUS_SEGMENT_NOTIFICATION";
    else if (info->ExceptionRecord->ExceptionCode == DBG_TERMINATE_THREAD) exceptionDesc = "DBG_TERMINATE_THREAD";
    else if (info->ExceptionRecord->ExceptionCode == DBG_TERMINATE_PROCESS) exceptionDesc = "DBG_TERMINATE_PROCESS";
    else if (info->ExceptionRecord->ExceptionCode == DBG_CONTROL_C) exceptionDesc = "DBG_CONTROL_C";
    else if (info->ExceptionRecord->ExceptionCode == DBG_PRINTEXCEPTION_C) exceptionDesc = "DBG_PRINTEXCEPTION_C";
    else if (info->ExceptionRecord->ExceptionCode == DBG_RIPEXCEPTION) exceptionDesc = "DBG_RIPEXCEPTION";
    else if (info->ExceptionRecord->ExceptionCode == DBG_CONTROL_BREAK) exceptionDesc = "DBG_CONTROL_BREAK";
    else if (info->ExceptionRecord->ExceptionCode == DBG_COMMAND_EXCEPTION) exceptionDesc = "DBG_COMMAND_EXCEPTION";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) exceptionDesc = "STATUS_GUARD_PAGE_VIOLATION";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_DATATYPE_MISALIGNMENT) exceptionDesc = "STATUS_DATATYPE_MISALIGNMENT";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT) exceptionDesc = "STATUS_BREAKPOINT";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP) exceptionDesc = "STATUS_SINGLE_STEP";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_LONGJUMP) exceptionDesc = "STATUS_LONGJUMP";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_UNWIND_CONSOLIDATE) exceptionDesc = "STATUS_UNWIND_CONSOLIDATE";
    else if (info->ExceptionRecord->ExceptionCode == DBG_EXCEPTION_NOT_HANDLED) exceptionDesc = "DBG_EXCEPTION_NOT_HANDLED";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION) exceptionDesc = "STATUS_ACCESS_VIOLATION";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_IN_PAGE_ERROR) exceptionDesc = "STATUS_IN_PAGE_ERROR";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_INVALID_HANDLE) exceptionDesc = "STATUS_INVALID_HANDLE";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_INVALID_PARAMETER) exceptionDesc = "STATUS_INVALID_PARAMETER";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_NO_MEMORY) exceptionDesc = "STATUS_NO_MEMORY";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_ILLEGAL_INSTRUCTION) exceptionDesc = "STATUS_ILLEGAL_INSTRUCTION";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_NONCONTINUABLE_EXCEPTION) exceptionDesc = "STATUS_NONCONTINUABLE_EXCEPTION";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_INVALID_DISPOSITION) exceptionDesc = "STATUS_INVALID_DISPOSITION";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_ARRAY_BOUNDS_EXCEEDED) exceptionDesc = "STATUS_ARRAY_BOUNDS_EXCEEDED";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_FLOAT_DENORMAL_OPERAND) exceptionDesc = "STATUS_FLOAT_DENORMAL_OPERAND";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_FLOAT_DIVIDE_BY_ZERO) exceptionDesc = "STATUS_FLOAT_DIVIDE_BY_ZERO";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_FLOAT_INEXACT_RESULT) exceptionDesc = "STATUS_FLOAT_INEXACT_RESULT";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_FLOAT_INVALID_OPERATION) exceptionDesc = "STATUS_FLOAT_INVALID_OPERATION";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_FLOAT_OVERFLOW) exceptionDesc = "STATUS_FLOAT_OVERFLOW";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_FLOAT_STACK_CHECK) exceptionDesc = "STATUS_FLOAT_STACK_CHECK";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_FLOAT_UNDERFLOW) exceptionDesc = "STATUS_FLOAT_UNDERFLOW";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_INTEGER_DIVIDE_BY_ZERO) exceptionDesc = "STATUS_INTEGER_DIVIDE_BY_ZERO";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_INTEGER_OVERFLOW) exceptionDesc = "STATUS_INTEGER_OVERFLOW";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_PRIVILEGED_INSTRUCTION) exceptionDesc = "STATUS_PRIVILEGED_INSTRUCTION";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_STACK_OVERFLOW) exceptionDesc = "STATUS_STACK_OVERFLOW";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_DLL_NOT_FOUND) exceptionDesc = "STATUS_DLL_NOT_FOUND";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_ORDINAL_NOT_FOUND) exceptionDesc = "STATUS_ORDINAL_NOT_FOUND";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_ENTRYPOINT_NOT_FOUND) exceptionDesc = "STATUS_ENTRYPOINT_NOT_FOUND";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_CONTROL_C_EXIT) exceptionDesc = "STATUS_CONTROL_C_EXIT";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_DLL_INIT_FAILED) exceptionDesc = "STATUS_DLL_INIT_FAILED";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_FLOAT_MULTIPLE_FAULTS) exceptionDesc = "STATUS_FLOAT_MULTIPLE_FAULTS";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_FLOAT_MULTIPLE_TRAPS) exceptionDesc = "STATUS_FLOAT_MULTIPLE_TRAPS";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_REG_NAT_CONSUMPTION) exceptionDesc = "STATUS_REG_NAT_CONSUMPTION";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_STACK_BUFFER_OVERRUN) exceptionDesc = "STATUS_STACK_BUFFER_OVERRUN";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_INVALID_CRUNTIME_PARAMETER) exceptionDesc = "STATUS_INVALID_CRUNTIME_PARAMETER";
    else if (info->ExceptionRecord->ExceptionCode == STATUS_ASSERTION_FAILURE) exceptionDesc = "STATUS_ASSERTION_FAILURE";


    Logger::getInstance()->write("POSSIBLE CRASH DETECTED!");
    Logger::getInstance()->write("\t%s at 0x%08x", exceptionDesc, info->ExceptionRecord->ExceptionAddress);
    Logger::getInstance()->write("\t%s", exceptionDesc);
    Logger::getInstance()->write("Exception Params: %d", info->ExceptionRecord->NumberParameters);
    for (unsigned int i = 0; i < info->ExceptionRecord->NumberParameters; i++)
        Logger::getInstance()->write("\t\tParam #%d: 0x%08x", i, info->ExceptionRecord->ExceptionInformation[i]);
    Logger::getInstance()->write("\tEAX: 0x%08x", info->ContextRecord->Eax);
    Logger::getInstance()->write("\tEBP: 0x%08x", info->ContextRecord->Ebp);
    Logger::getInstance()->write("\tEBX: 0x%08x", info->ContextRecord->Ebx);
    Logger::getInstance()->write("\tECX: 0x%08x", info->ContextRecord->Ecx);
    Logger::getInstance()->write("\tEDI: 0x%08x", info->ContextRecord->Edi);
    Logger::getInstance()->write("\tEDX: 0x%08x", info->ContextRecord->Edx);
    Logger::getInstance()->write("\tESI: 0x%08x", info->ContextRecord->Esi);
    Logger::getInstance()->write("\tESP: 0x%08x", info->ContextRecord->Esp);
    Logger::getInstance()->write("\tEIP: 0x%08x", info->ContextRecord->Eip);
    Logger::getInstance()->write("\tEFLAGS: 0x%08x", info->ContextRecord->EFlags);


    return EXCEPTION_CONTINUE_SEARCH;
}