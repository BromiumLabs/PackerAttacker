#pragma once
#include <Windows.h>
#include <string>

// ditching this for now
#ifdef 0

template<typename T, int SIZE>
struct SharedMemoryDefinition
{
    unsigned int elementCount;
    T elements[SIZE];
};

template<typename T, int SIZE>
class SharedMemoryArray
{
public:

    SharedMemoryArray(std::string _name) : name(_name), sharedMemoryHande(INVALID_HANDLE_VALUE), SharedMemoryDefinition(NULL) {}
    ~SharedMemoryArray(void)
    {
    }

    bool initialize()
    {
        /* don't need to try if we already have a handle */
        if (this->sharedMemoryHande != INVALID_HANDLE_VALUE)
            return true;

        this->sharedMemoryHande = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(SharedMemoryDefinition<T, SIZE>), this->name.c_str());

        /* make sure it succeeded */
        if (this->sharedMemoryHande == INVALID_HANDLE_VALUE)
            return false;

        /* get a pointer to it and zero it out if we're the first holder */
        bool Created = (GetLastError() != ERROR_ALREADY_EXISTS);
        this->sharedMemorySegment = (SharedMemoryDefinition<T, SIZE>*)MapViewOfFile(this->sharedMemorySegment, FILE_MAP_WRITE, 0, 0, 0);
        if (Created)
            ZeroMemory(this->sharedMemorySegment, sizeof(SharedMemoryDefinition<T, SIZE>));

        return true;
    }

    bool addElement(T value)
    {
        if (this->sharedMemorySegment->elementCount == SIZE)
            return false;

        this->sharedMemorySegment->elements[this->sharedMemorySegment->elementCount] = value;
        this->sharedMemorySegment->elementCount++;

        return true;
    }

    T getElement(unsigned int index)
    {
        return this->sharedMemorySegment->elements[index];
    }

private:


    std::string name;
    HANDLE sharedMemoryHande;
    SharedMemoryDefinition<T, SIZE>* sharedMemorySegment;
};

#endif