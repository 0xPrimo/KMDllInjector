#include "PIC.h"

/**
 * @brief Position Independent Code (PIC) Hook for intercepting calls to LdrLoadDll.
 */
#pragma optimize("", off)
#pragma code_seg(".text$A")
__declspec( safebuffers )
NTSTATUS HookLdrLoadDll( PWCHAR pwPathToFile, ULONG ulFlags, PUNICODE_STRING puModuleFileName, PHANDLE phModuleHandle )
{
	NTSTATUS status = STATUS_SUCCESS;
	PHOOK_CONTEXT pContext = ( PHOOK_CONTEXT ) 0xBAADF00DBAADBEEF; // The driver will replace this with the address to the allocated and initialized context
	PVOID pLdrLoadDll = NULL;
	SIZE_T sNumberOfBytes = 12;
	DWORD dwOldProtect = 0;
	HANDLE hModule;
	UNICODE_STRING uMyDll;
	PVOID pBuffer = NULL;

	pBuffer = pLdrLoadDll = ( PVOID ) pContext->Win32.LdrLoadDll;
	status = pContext->Win32.NtProtectVirtualMemory( ( HANDLE ) -1, &pBuffer, ( PULONG ) &sNumberOfBytes, PAGE_EXECUTE_READWRITE, &dwOldProtect );
	if ( !NT_SUCCESS( status ) )
		return status;

	MEMCPY( pLdrLoadDll, pContext->SavedBytes, 12 );

	status = pContext->Win32.NtProtectVirtualMemory( ( HANDLE ) -1, &pBuffer, ( PULONG ) &sNumberOfBytes, PAGE_EXECUTE_READWRITE, &dwOldProtect );
	if ( !NT_SUCCESS( status ) )
		return status;

	status = pContext->Win32.LdrLoadDll( pwPathToFile, ulFlags, puModuleFileName, phModuleHandle );
	if ( !NT_SUCCESS( status ) )
		return status;

	pContext->Win32.RtlInitUnicodeString( &uMyDll, pContext->ModuleFileName );
	status = pContext->Win32.LdrLoadDll( NULL, 0, &uMyDll, &hModule );
	if ( !NT_SUCCESS( status ) )
		return status;

	return status;
}
#pragma code_seg(".text$B")
DWORD HookLdrLoadDllEnd( ) {
	return 2;
}

/**
 * @brief APC callback function for loading a DLL in a target process.
 *
 * @param LdrLoadDllCall A pointer to an LDR_LOAD_DLL_CALL structure containing
 *                        the necessary parameters for calling LdrLoadDll.
 */
#pragma code_seg(".text$C")
VOID APCCallback( PLDR_LAOD_DLL_CALL LdrLoadDllCall ) {
	LdrLoadDllCall->LdrLoadDll( LdrLoadDllCall->PathToFile, LdrLoadDllCall->Flags, &LdrLoadDllCall->uModuleFileName, &LdrLoadDllCall->ModuleHandle );
}
#pragma code_seg(".text$D")
DWORD APCCallbackEnd( ) {
	return 1;
}

#pragma code_seg()
#pragma optimize("", on)
