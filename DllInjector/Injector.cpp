#include "Utils.h"
#include "Injector.h"

/******************************************************************
*		  Inject Shellcode + Hook LdrLoadDll Technique
*******************************************************************/

/**
 * @brief Injects a DLL into a process by hooking LdrLoadDll.
 *
 * @param pProcess		A pointer to the EPROCESS structure of the target process.
 * @param pwDllToInject A pointer to a wide-character string containing the full path
 *                      of the DLL to be injected.
 *
 * @return TRUE if the injection was successful, FALSE otherwise.
 */
BOOL Injector::InjectDllHook( PEPROCESS pProcess, PWCH pwDllToInject )
{
	BOOL bStatus = FALSE;
	NTSTATUS ntStatus = STATUS_SUCCESS;
	KAPC_STATE kapcState = { 0 };
	PBYTE pbNtdll = NULL;
	PVOID pLdrLoadDll = NULL;
	HOOK_CONTEXT HookContext;
	SIZE_T sHookFuncSize = 0;
	PVOID pBuffer = NULL;
	SIZE_T sTotalSize = 0;
	DWORD dwOldProtect = 0;
	SIZE_T sBytesSize = 12;
	PVOID pFunctionBuffer = NULL;
	PBYTE pbFunctionStart = NULL;
	BOOL bIsFound = FALSE;
	BYTE bTrampoline[ ] = {
		0x48, 0xB8, 00, 00, 00, 00, 00, 00, 00, 00,		// mov rax, <address>
		0xFF, 0xE0										// jmp rax
	};


	KeStackAttachProcess( pProcess, &kapcState );
	ntStatus = Utils::GetNtdllBaseAddress( pProcess, ( PVOID* ) &pbNtdll );
	if ( !NT_SUCCESS( ntStatus ) )
	{
		DBG_PRINT( "Failed to get ntdll base address" );
		goto __END;
	}

	pLdrLoadDll = HookContext.Win32.LdrLoadDll = ( LDRLOADDLL ) Utils::GetProcAddress( pbNtdll, "LdrLoadDll" );
	if ( !HookContext.Win32.LdrLoadDll )
	{
		DBG_PRINT( "Failed to get LdrLoadDll function address" );
		goto __END;
	}

	HookContext.Win32.RtlInitUnicodeString = ( RTLINITUNICODESTRING ) Utils::GetProcAddress( pbNtdll, "RtlInitUnicodeString" );
	if ( !HookContext.Win32.RtlInitUnicodeString )
	{
		DBG_PRINT( "Failed to get RtlInitUnicodeString function address" );
		goto __END;
	}

	HookContext.Win32.NtProtectVirtualMemory = ( NTPROTECTVIRTUALMEMORY ) Utils::GetProcAddress( pbNtdll, "NtProtectVirtualMemory" );
	if ( !HookContext.Win32.NtProtectVirtualMemory )
	{
		DBG_PRINT( "Failed to get NtProtectVirtualMemory function address" );
		goto __END;
	}

	sHookFuncSize = ( ( DWORD_PTR ) HookLdrLoadDllEnd ) - ( ( DWORD_PTR ) HookLdrLoadDll );
	sTotalSize = sHookFuncSize + sizeof( HOOK_CONTEXT );

	ntStatus = ZwAllocateVirtualMemory( NtCurrentProcess( ), &pBuffer, 0, &sTotalSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
	if ( !NT_SUCCESS( ntStatus ) )
	{
		DBG_PRINT( "ZwAllocateVirtualMemory failed with error code %d", ntStatus );
		goto __END;
	}


	RtlCopyMemory( HookContext.SavedBytes, HookContext.Win32.LdrLoadDll, 12 );
	wcscpy( HookContext.ModuleFileName, pwDllToInject );

	RtlCopyMemory( pBuffer, &HookContext, sizeof( HOOK_CONTEXT ) );
	RtlCopyMemory( ( PVOID ) ( ( DWORD_PTR ) pBuffer + sizeof( HOOK_CONTEXT ) ), HookLdrLoadDll, sHookFuncSize );

	pbFunctionStart = ( PBYTE ) ( ( DWORD_PTR ) pBuffer + sizeof( HOOK_CONTEXT ) );
	for ( DWORD dwIndex = 0; dwIndex < sTotalSize; dwIndex++ )
	{
		if ( *( DWORD64* ) ( pbFunctionStart + dwIndex ) == 0xBAADF00DBAADBEEF )
		{
			*( DWORD64* ) ( pbFunctionStart + dwIndex ) = ( DWORD64 ) pBuffer;
			bIsFound = TRUE;
			break;
		}
	}

	if ( !bIsFound )
	{
		DBG_PRINT( "Couldn't find the pattern in function" );
		goto __END;
	}

	pFunctionBuffer = pLdrLoadDll;
	*( DWORD64* ) ( bTrampoline + 2 ) = ( DWORD64 ) pbFunctionStart;

	ntStatus = ZwProtectVirtualMemory( ZwCurrentProcess( ), &pFunctionBuffer, ( PULONG ) &sBytesSize, PAGE_EXECUTE_READWRITE, &dwOldProtect );
	if ( !NT_SUCCESS( ntStatus ) )
	{
		DBG_PRINT( "NtProtectVirtualMemory failed with error code %d", ntStatus );
		goto __END;
	}

	RtlCopyMemory( pLdrLoadDll, bTrampoline, 12 );

	ntStatus = ZwProtectVirtualMemory( ZwCurrentProcess( ), &pFunctionBuffer, ( PULONG ) &sBytesSize, dwOldProtect, &dwOldProtect );
	if ( !NT_SUCCESS( ntStatus ) )
	{
		DBG_PRINT( "NtProtectVirtualMemory failed with error code %d", ntStatus );
		goto __END;
	}

	bStatus = TRUE;
__END:
	KeUnstackDetachProcess( &kapcState );
	return bStatus;
}

/******************************************************************
*			  Asynchronous Procedure Call Technique
*******************************************************************/

VOID KernelAPC( PVOID, PVOID, PVOID, PVOID, PVOID ) { }

/**
 * @brief Injects a DLL into a process using an Asynchronous Procedure Call (APC).
 *
 * @param ProcessPid	The process identifier (PID) of the target process.
 * @param DllToInject	A pointer to a wide-character string containing the full path
 *						of the DLL to be injected.
 *
 * @return TRUE if the injection was successful, FALSE otherwise.
 */
BOOL Injector::InjectDllAPC( HANDLE ProcessPid, PWCH DllToInject )
{
	NTSTATUS status = 0;
	BOOL bStatus = FALSE;
	PEPROCESS Process = NULL;
	PETHREAD Thread = NULL;
	KAPC_STATE apcState = { 0 };
	PBYTE pNtdll = NULL;
	PVOID pLdrLoadDll = NULL;
	PLDR_LAOD_DLL_CALL pArguments = NULL;
	SIZE_T sArgumentsSize = sizeof( LDR_LAOD_DLL_CALL );
	SIZE_T sAPCCallbackSize = 0, stempAPCCallbackSize = 0;
	PVOID pAPCCallbackCodeCave = NULL;
	HANDLE ThreadId = 0;
	PKAPC apc = 0;

	status = PsLookupProcessByProcessId( ProcessPid, &Process );
	if ( !NT_SUCCESS( status ) )
		return FALSE;

	KeStackAttachProcess( Process, &apcState );

	pNtdll = ( PBYTE ) Utils::GetModuleHandle( Process, L"ntdll.dll" );
	if ( !pNtdll )
		goto __END;

	pLdrLoadDll = Utils::GetProcAddress( pNtdll, "LdrLoadDll" );
	if ( !pLdrLoadDll )
		goto __END;

	status = ZwAllocateVirtualMemory( NtCurrentProcess( ), ( PVOID* ) &pArguments, 0, &sArgumentsSize, MEM_COMMIT, PAGE_READWRITE );
	if ( !NT_SUCCESS( status ) )
		goto __END;

	RtlZeroMemory( pArguments, sArgumentsSize );

	pArguments->PathToFile = NULL;
	pArguments->Flags = 0;
	pArguments->LdrLoadDll = ( LDRLOADDLL ) pLdrLoadDll;
	pArguments->uModuleFileName.Buffer = pArguments->pwBuffer;
	wcscpy( pArguments->pwBuffer, DllToInject );
	pArguments->uModuleFileName.Length = ( USHORT ) ( wcslen( DllToInject ) * sizeof( WCHAR ) );
	pArguments->uModuleFileName.MaximumLength = sizeof( WCHAR ) * MAX_PATH;
	pArguments->hModule = NULL;

	sAPCCallbackSize = ( ( DWORD_PTR ) APCCallbackEnd ) - ( ( DWORD_PTR ) APCCallback );
	stempAPCCallbackSize = sAPCCallbackSize;
	pAPCCallbackCodeCave = NULL;

	status = ZwAllocateVirtualMemory( NtCurrentProcess( ), &pAPCCallbackCodeCave, 0, &stempAPCCallbackSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
	if ( !NT_SUCCESS( status ) )
		goto __END;

	RtlCopyMemory( pAPCCallbackCodeCave, APCCallback, sAPCCallbackSize );

	ThreadId = Utils::GetMainThreadId( ProcessPid );
	if ( !ThreadId )
		goto __END;

	status = PsLookupThreadByThreadId( ThreadId, &Thread );
	if ( !NT_SUCCESS( status ) )
	{
		DBG_PRINT( "PsLookupThreadByThreadId failed with code %X", status );
		goto __END;
	}

	KeUnstackDetachProcess( &apcState );
	apc = ( PKAPC ) ExAllocatePool2( POOL_FLAG_NON_PAGED, sizeof( KAPC ), POOL_TAG );
	if ( apc == NULL )
		goto __END_1;

	KeInitializeApc( apc,
					 Thread,
					 OriginalApcEnvironment,
					 ( PKKERNEL_ROUTINE ) KernelAPC,
					 NULL,
					 ( PKNORMAL_ROUTINE ) pAPCCallbackCodeCave,
					 UserMode,
					 pArguments );

	if ( !KeInsertQueueApc( apc, NULL, NULL, 0 ) ) {
		ExFreePool( apc );
		goto __END_1;
	}

	bStatus = TRUE;
	goto __END_1;

__END:
	if ( pAPCCallbackCodeCave ) {
		status = ZwFreeVirtualMemory( NtCurrentProcess( ), &pAPCCallbackCodeCave, &stempAPCCallbackSize, MEM_RELEASE );
		if ( !NT_SUCCESS( status ) )
			DBG_PRINT( "ZwFreeVirtualMemory failed with code %X\n", status );
	}

	if ( pArguments ) {
		status = ZwFreeVirtualMemory( NtCurrentProcess( ), ( PVOID* ) &pArguments, &sArgumentsSize, MEM_RELEASE );
		if ( !NT_SUCCESS( status ) )
			DBG_PRINT( "ZwFreeVirtualMemory failed with code %X\n", status );
	}

	KeUnstackDetachProcess( &apcState );

__END_1:
	if ( Thread )
		ObDereferenceObject( Thread );
	if ( Process )
		ObDereferenceObject( Process );

	return bStatus;
}