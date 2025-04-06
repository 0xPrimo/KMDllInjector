#pragma once

#include "Common.h"

#define MEM_IMAGE		0x1000000

class Utils {
public:
	static BOOLEAN	EndsWithUnicodeString( PUNICODE_STRING FullName, PUNICODE_STRING ShortName, BOOLEAN CaseInsensitive );
	static BOOLEAN	IsLoadedByLdrLoadDll( PUNICODE_STRING ShortName );
	static BOOLEAN	IsSpecificProcessW( HANDLE ProcessId, const WCHAR* ImageName, BOOLEAN bIsDebugged );
	static PVOID	GetModuleHandle( PEPROCESS Process, LPCWCH lpcModuleName );
	static NTSTATUS GetNtdllBaseAddress( PVOID* NtdllBase );
	static PVOID	GetProcAddress( PBYTE hModule, LPCSTR lpcFuncName );
	static HANDLE	GetMainThreadId( HANDLE ProcessId );
};