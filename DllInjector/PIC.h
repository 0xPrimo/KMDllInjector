#pragma once

#include <ntifs.h>
#include <minwindef.h>

// 
// https://5pider.net/blog/2024/01/27/modern-shellcode-implant-design/
//

#define MEMSET(dst, val, size) __stosb( ( unsigned char* ) dst, ( unsigned char ) val, size )
#define MEMCPY(dst, src, size) __movsb( (PUCHAR)dst, (const UCHAR *)src, size)

typedef VOID( *RTLINITUNICODESTRING )(
	PUNICODE_STRING         DestinationString,
	PCWSTR SourceString
	);

typedef NTSTATUS( NTAPI* NTPROTECTVIRTUALMEMORY )(
	IN HANDLE               ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PULONG           NumberOfBytesToProtect,
	IN ULONG                NewAccessProtection,
	OUT PULONG              OldAccessProtection );

typedef NTSTATUS( NTAPI* LDRLOADDLL )(
	IN PWCHAR               PathToFile OPTIONAL,
	IN ULONG                Flags OPTIONAL,
	IN PUNICODE_STRING      ModuleFileName,
	OUT PHANDLE             ModuleHandle );

typedef struct {
	LDRLOADDLL				LdrLoadDll;
	PWCHAR					PathToFile;
	ULONG					Flags;
	HANDLE					ModuleHandle;

	WCHAR					pwBuffer[ MAX_PATH * sizeof( WCHAR ) ];
	UNICODE_STRING			uModuleFileName;
	HANDLE					hModule;
} LDR_LAOD_DLL_CALL, * PLDR_LAOD_DLL_CALL;

typedef struct {
	BYTE SavedBytes[ 12 ];
	WCHAR ModuleFileName[ MAX_PATH ];

	struct {
		LDRLOADDLL				LdrLoadDll;
		NTPROTECTVIRTUALMEMORY	NtProtectVirtualMemory;
		RTLINITUNICODESTRING	RtlInitUnicodeString;
	} Win32;
} HOOK_CONTEXT, * PHOOK_CONTEXT;