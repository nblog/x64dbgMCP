
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>


EXTERN_C
__declspec(dllexport)
VOID __dummy__()
{
    return;
}


// push managed state on to stack and set unmanaged state
#pragma managed(push, off)


BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: {
        DisableThreadLibraryCalls(hModule);
        break;
    }
    case DLL_PROCESS_DETACH:
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}

#pragma managed(pop)