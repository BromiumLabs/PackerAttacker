#pragma once
#include <Windows.h>

template<typename T> static T AdjustPointerRVA(DWORD rva, IMAGE_NT_HEADERS* ntHeader, BYTE* imageBase)
{
	auto pSectionHdr = GetEnclosingSectionHeader(rva, ntHeader);
	if (!pSectionHdr)
		return 0;
	int delta = (int)(pSectionHdr->VirtualAddress-pSectionHdr->PointerToRawData);
	return (T)((void*)(imageBase + rva - delta));
}
template<typename T, typename Tp> static T MakePointer(Tp pointer, DWORD_PTR addition)
{
	return (T)((DWORD_PTR)pointer + (DWORD_PTR)addition);
}

template<typename T, typename Ta, typename Tb> static T GetDelta(Ta a, Tb b)
{
	return (T)((DWORD_PTR)a - (DWORD_PTR)b);
}