#include "SyncLock.h"

SyncLockScopeGuard::SyncLockScopeGuard(SyncLock* _lock) : lock(_lock)
{
    this->lock->enter();
}
SyncLockScopeGuard::~SyncLockScopeGuard(void)
{
    this->lock->leave();
}

SyncLock::SyncLock(void) 
{
    InitializeCriticalSection(&this->lock);
}
SyncLock::~SyncLock(void)
{
    DeleteCriticalSection(&this->lock);
}

void SyncLock::enter()
{
    EnterCriticalSection(&this->lock);
}

void SyncLock::leave()
{
    LeaveCriticalSection(&this->lock);
}
