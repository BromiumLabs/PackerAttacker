#pragma once
#include <Windows.h>
#include <list>
#include <vector>

struct TrackedMemoryBlock
{
    DWORD startAddress, endAddress, size;
    DWORD neededProtection;

    TrackedMemoryBlock(DWORD _startAddress, DWORD _size, DWORD _neededProtection = NULL)
    {
        this->startAddress = _startAddress;
        this->endAddress = _startAddress + _size;
        this->size = _size;
        this->neededProtection = _neededProtection;
    }

    bool overlapsWith(TrackedMemoryBlock right, bool oneSided = false)
    {
        if (!oneSided)
            if (right.overlapsWith(*this, true))
                return true;
        return (right.startAddress >= this->startAddress && right.startAddress <= this->endAddress);
    }

    virtual void mergeWith(TrackedMemoryBlock right)
    {
        DWORD protectionTemp = right.neededProtection;
        if (this->overlapsWith(right, true))
        {
            this->endAddress = right.endAddress;
            this->size = this->endAddress - this->startAddress;
        }
        else if (right.overlapsWith(*this, true))
        {
            TrackedMemoryBlock temp(right);
            temp.mergeWith(*this);

            this->startAddress = temp.startAddress;
            this->endAddress = temp.endAddress;
            this->size = temp.size;
        }
        else
            return;

        this->neededProtection = protectionTemp;
    }
};


struct TrackedCopiedMemoryBlock : public TrackedMemoryBlock
{
    std::vector<unsigned char> buffer;
    TrackedCopiedMemoryBlock(DWORD _startAddress, DWORD _size, unsigned char* _buffer)
        : TrackedMemoryBlock(_startAddress, _size, PAGE_NOACCESS)
    {
        this->buffer.reserve(size);
        for (unsigned int i = 0; i < size; i++)
            this->buffer.push_back(_buffer[i]);
    }

    virtual void mergeWith(TrackedCopiedMemoryBlock right)
    {
        DWORD protectionTemp = right.neededProtection;
        if (this->overlapsWith(right, true))
        {
            /* we need to copy on top of existing bytes */
            unsigned int startIndex = right.startAddress - this->startAddress;
            unsigned int oI = startIndex; //overwrite index
            unsigned int cI = 0; //copy index

            /* copy over existing data */
            for (; oI < this->size; oI++, cI++)
                this->buffer[oI] = right.buffer[cI];

            /* copy over trailing data */
            for (; cI < right.size; cI++, oI++)
            {
                assert(oI <= this->buffer.size());
                if (oI == this->buffer.size())
                    this->buffer.push_back(right.buffer[cI]);
                else
                    this->buffer[oI] = right.buffer[cI];
            }

            this->endAddress = right.endAddress;
            this->size = this->endAddress - this->startAddress;
        }
        else if (right.overlapsWith(*this, true))
        {
            TrackedCopiedMemoryBlock temp(right);
            temp.mergeWith(*this);

            this->startAddress = temp.startAddress;
            this->endAddress = temp.endAddress;
            this->size = temp.size;
            this->buffer = temp.buffer;
        }
        else
            return;

        this->neededProtection = protectionTemp;
    }
};

template<typename TrackType>
struct MemoryBlockTracker
{
    std::list<TrackType> trackedMemoryBlocks;

    typename std::list<TrackType>::iterator nullMarker()
    {
        return this->trackedMemoryBlocks.end();
    }
    typename std::list<TrackType>::iterator findTracked(DWORD address, DWORD size)
    {
        return findTracked(TrackType(address, size));
    }
    typename std::list<TrackType>::iterator findTracked(TrackType check)
    {
        for (auto it = this->trackedMemoryBlocks.begin(); it != this->trackedMemoryBlocks.end(); it++)
            if (it->overlapsWith(check))
                return it;

        return this->trackedMemoryBlocks.end();
    }
    bool isTracked(DWORD address, DWORD size)
    {
        return isTracked(TrackType(address, size));
    }
    bool isTracked(TrackedMemoryBlock check)
    {
        return findTracked(check) != this->nullMarker();
    }
    void startTracking(DWORD address, DWORD size, DWORD protection)
    {
        startTracking(TrackType(address, size, protection));
    }
    void startTracking(TrackType right)
    {
        auto it = this->findTracked(right);
        if (it != this->nullMarker())
            it->mergeWith(right);
        else
            this->trackedMemoryBlocks.push_back(right);
    }
    void stopTracking(DWORD address, DWORD size)
    {
        this->stopTracking(this->findTracked(address, size));
    }
    void stopTracking(typename std::list<TrackType>::iterator it)
    {
        assert(it != this->trackedMemoryBlocks.end());

        this->trackedMemoryBlocks.erase(it);
    }
};