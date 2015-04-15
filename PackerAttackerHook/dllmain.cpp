#include <windows.h>
#include "UnpackingEngine.h"


DWORD WINAPI initThread(LPVOID lpParameter)
{
    UnpackingEngine::getInstance()->initialize();
    return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
        {
            UnpackingEngine::getInstance()->initialize();
        }
        break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
        break;
	case DLL_PROCESS_DETACH:
        UnpackingEngine::getInstance()->uninitialize();
		break;
	}
	return TRUE;
}

