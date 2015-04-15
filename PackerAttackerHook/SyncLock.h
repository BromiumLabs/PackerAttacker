#pragma once
#include <Windows.h>
#include <memory>

class SyncLock;
class SyncLockScopeGuard
{
public:
    SyncLockScopeGuard(SyncLock* _lock);
    ~SyncLockScopeGuard(void);

private:
    SyncLock* lock;
};


class SyncLock
{
public:
    SyncLock(void);
    ~SyncLock(void);

    void enter();
    void leave();

    inline std::shared_ptr<SyncLockScopeGuard> SyncLock::enterWithScopeGuard()
    {
        return std::shared_ptr<SyncLockScopeGuard>(new SyncLockScopeGuard(this));
    }

private:
    CRITICAL_SECTION lock;
};
