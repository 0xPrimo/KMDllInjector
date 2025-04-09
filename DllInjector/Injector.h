#pragma once

#include <ntifs.h>
#include <minwindef.h>

#include "Common.h"
#include "PIC.h"

NTSTATUS HookLdrLoadDll( PWCHAR pwPathToFile, ULONG ulFlags, PUNICODE_STRING puModuleFileName, PHANDLE phModuleHandle );
DWORD HookLdrLoadDllEnd( );
VOID APCCallback( PLDR_LAOD_DLL_CALL LdrLoadDllCall );
DWORD APCCallbackEnd( );

class Injector {
public:
	static BOOL InjectDllAPC( HANDLE ProcessPid, PWCH DllToInject );
	static BOOL InjectDllHook( PEPROCESS Process, PWCH DllToInject );
};