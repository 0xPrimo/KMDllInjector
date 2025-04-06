// Utils.cpp

#include "Utils.h"

BOOLEAN IsDllModule( PVOID BaseAddress )
{
	PIMAGE_DOS_HEADER dosHeader = ( PIMAGE_DOS_HEADER ) BaseAddress;

	if ( dosHeader->e_magic != IMAGE_DOS_SIGNATURE ) {
		return FALSE;
	}

	PIMAGE_NT_HEADERS ntHeaders = ( PIMAGE_NT_HEADERS ) ( ( ULONG_PTR ) BaseAddress + dosHeader->e_lfanew );

	if ( ntHeaders->Signature != IMAGE_NT_SIGNATURE ) {
		return FALSE;
	}

	if ( ntHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL ) {
		return TRUE;
	}

	return FALSE;
}

NTSTATUS Utils::GetNtdllBaseAddress( PVOID* NtdllBase )
{
	MEMORY_BASIC_INFORMATION memInfo;
	SIZE_T returnLength;
	PVOID baseAddress = NULL;
	NTSTATUS status;


	// Start from address 0 and scan memory regions
	while ( TRUE ) {
		status = ZwQueryVirtualMemory(
			ZwCurrentProcess( ),
			baseAddress,
			MemoryBasicInformation,
			&memInfo,
			sizeof( memInfo ),
			&returnLength
		);

		if ( !NT_SUCCESS( status ) ) {
			break;
		}

		// Check if this region is a mapped image
		if ( memInfo.Type == MEM_IMAGE ) {
			// You need a way to identify NTDLL - one approach is to check for known patterns
			// or read the PE headers to identify NTDLL.dll
			if ( IsDllModule( memInfo.BaseAddress ) ) {

				DBG_PRINT( "Ntdll: %p", memInfo.BaseAddress );
				*NtdllBase = memInfo.BaseAddress;
				return STATUS_SUCCESS;
			}
		}

		// Move to the next region
		baseAddress = ( PVOID ) ( ( ULONG_PTR ) memInfo.BaseAddress + memInfo.RegionSize );
	}

	return STATUS_NOT_FOUND;
}

PVOID Utils::GetModuleHandle( PEPROCESS Process, LPCWCH lpcModuleName )
{
	UNICODE_STRING	uModuleName = { 0 };
	PLIST_ENTRY		pListEntry = NULL;
	PPEB			pPeb = NULL;

	RtlInitUnicodeString( &uModuleName, lpcModuleName );
	pPeb = PsGetProcessPeb( Process );
	if ( !pPeb )
		return NULL;

	for ( pListEntry = pPeb->LoaderData->InLoadOrderModuleList.Flink;
		  pListEntry != &pPeb->LoaderData->InLoadOrderModuleList;
		  pListEntry = pListEntry->Flink ) {

		PLDR_MODULE pEntry = CONTAINING_RECORD( pListEntry, LDR_MODULE, InLoadOrderModuleList );

		if ( pEntry->BaseDllName.Length > 0 ) {

			if ( RtlCompareUnicodeString( &pEntry->BaseDllName, &uModuleName, TRUE ) == 0 )
				return pEntry->BaseAddress;
		}
	}

	return NULL;
}

PVOID Utils::GetProcAddress( PBYTE hModule, LPCSTR lpcFuncName )
{
	PIMAGE_DOS_HEADER pDosHdr = NULL;
	PIMAGE_NT_HEADERS pNtHdrs = NULL;
	IMAGE_OPTIONAL_HEADER pOptionalHdr = { 0 };
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
	PVOID pFuncAddress = NULL;

	pDosHdr = ( PIMAGE_DOS_HEADER ) hModule;
	if ( !pDosHdr )
		return NULL;

	if ( pDosHdr->e_magic != IMAGE_DOS_SIGNATURE )
		return NULL;

	pNtHdrs = ( PIMAGE_NT_HEADERS ) ( hModule + pDosHdr->e_lfanew );
	if ( pNtHdrs->Signature != IMAGE_NT_SIGNATURE )
		return NULL;

	pOptionalHdr = pNtHdrs->OptionalHeader;
	if ( pOptionalHdr.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress == 0 )
		return NULL;

	pExportDirectory = ( PIMAGE_EXPORT_DIRECTORY ) ( hModule + pOptionalHdr.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );

	// Iterating the export directory.
	DWORD* addresses = ( DWORD* ) ( hModule + pExportDirectory->AddressOfFunctions );
	WORD* ordinals = ( WORD* ) ( hModule + pExportDirectory->AddressOfNameOrdinals );
	DWORD* names = ( DWORD* ) ( hModule + pExportDirectory->AddressOfNames );
	for ( DWORD j = 0; j < pExportDirectory->NumberOfNames; j++ ) {
		if ( _stricmp( ( char* ) ( hModule + names[ j ] ), lpcFuncName ) == 0 ) {
			pFuncAddress = hModule + addresses[ ordinals[ j ] ];
			return pFuncAddress;
		}
	}

	return NULL;
}

HANDLE Utils::GetMainThreadId( HANDLE ProcessId )
{
	SIZE_T sSystemProcInfoSize = 0;
	PSYSTEM_PROCESS_INFO pSystemProcInfo = NULL, pTempPtr = NULL;
	NTSTATUS status = 0;
	HANDLE ThreadId = NULL;


	ZwQuerySystemInformation( SystemProcessInformation, NULL, NULL, ( PULONG ) &sSystemProcInfoSize );

	pTempPtr = pSystemProcInfo = ( PSYSTEM_PROCESS_INFO ) ExAllocatePool2( POOL_FLAG_NON_PAGED, sSystemProcInfoSize, POOL_TAG );;
	if ( pSystemProcInfo == NULL )
	{
		DBG_PRINT( "ExAllocatePool2 failed" );
		return NULL;
	}

	status = ZwQuerySystemInformation( SystemProcessInformation, pSystemProcInfo, ( ULONG ) sSystemProcInfoSize, ( PULONG ) &sSystemProcInfoSize );
	if ( !NT_SUCCESS( status ) )
	{
		DBG_PRINT( "ZwQuerySystemInformation failed with code %X", status );
		goto _END;
	}

	// Enumerating running processes
	while ( TRUE )
	{
		if ( pSystemProcInfo->UniqueProcessId == ProcessId )
		{
			ThreadId = pSystemProcInfo->Threads[ 0 ].ClientId.UniqueThread;
			break;
		}

		if ( pSystemProcInfo->NextEntryOffset == NULL )
			break;

		pSystemProcInfo = ( PSYSTEM_PROCESS_INFO ) ( ( DWORD_PTR ) pSystemProcInfo + pSystemProcInfo->NextEntryOffset );
	}

_END:
	if ( pTempPtr )
		ExFreePool( pTempPtr );
	return ThreadId;
}


/*
* @brief	EndsWithUnicodeString Checks if the 'FullName' is suffix/end with 'ShortName'.
* @param	FullName	Unicode string to check
* @param	ShortName	Suffix
* @param	CaseInsensitive
*/
BOOLEAN Utils::EndsWithUnicodeString( PUNICODE_STRING FullName, PUNICODE_STRING ShortName, BOOLEAN CaseInsensitive )
{
	if ( FullName && ShortName && ShortName->Length <= FullName->Length )
	{
		UNICODE_STRING uString = {
			ShortName->Length,
			uString.Length,
			( PWSTR ) RtlOffsetToPointer( FullName->Buffer, FullName->Length - uString.Length )
		};

		return RtlEqualUnicodeString( &uString, ShortName, CaseInsensitive );
	}

	return FALSE;
}

/*
* @brief	IsLoadedByLdrLoadDll checks if the module is loaded by LdrLoadDll API
* @param	ShortName	module name to check for
*/
BOOLEAN Utils::IsLoadedByLdrLoadDll( PUNICODE_STRING ShortName )
{
	UNICODE_STRING Name = { 0 };

	__try
	{
		PNT_TIB Teb = ( PNT_TIB ) PsGetCurrentThreadTeb( );

		if ( !Teb || !Teb->ArbitraryUserPointer )
			return FALSE;

		Name.Buffer = ( PWSTR ) Teb->ArbitraryUserPointer;

		// check if we have valid user-mode address
		ProbeForRead( Name.Buffer, sizeof( WCHAR ), __alignof( WCHAR ) );

		// check buffer length
		Name.Length = ( USHORT ) wcsnlen( Name.Buffer, MAXSHORT );
		if ( Name.Length == MAXSHORT )
		{
			DBG_PRINT( "Name is too long" );
			return FALSE;
		}

		Name.Length *= sizeof( WCHAR );
		Name.MaximumLength = Name.Length;

		return EndsWithUnicodeString( &Name, ShortName, TRUE );
	}
	__except ( EXCEPTION_EXECUTE_HANDLER )
	{
		DBG_PRINT( "Exception: (0x%X)", GetExceptionCode( ) );
	}

	return FALSE;
}

BOOLEAN Utils::IsSpecificProcessW( HANDLE ProcessId, const WCHAR* ImageName, BOOLEAN bIsDebugged )
{
	ASSERT( ImageName );
	BOOLEAN			bResult = FALSE;
	NTSTATUS		status = 0;
	PEPROCESS		Process = NULL;

	status = PsLookupProcessByProcessId( ProcessId, &Process );
	if ( NT_SUCCESS( status ) )
	{

		if ( !bIsDebugged ||
			 PsIsProcessBeingDebugged( Process ) )
		{
			HANDLE hProcess = NULL;

			if ( ObOpenObjectByPointer( Process, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &hProcess ) == STATUS_SUCCESS )
			{
				WCHAR buff[ sizeof( UNICODE_STRING ) + ( MAX_PATH + 1 ) * sizeof( WCHAR ) ];
				PUNICODE_STRING puProcessName = ( PUNICODE_STRING ) buff;
				PWCH pwBuff = ( PWCH ) ( ( PBYTE ) buff + sizeof( UNICODE_STRING ) );

				puProcessName->Length = 0;
				puProcessName->MaximumLength = ( USHORT ) ( sizeof( buff ) - sizeof( UNICODE_STRING ) );
				puProcessName->Buffer = pwBuff;

				if ( ZwQueryInformationProcess( hProcess, ProcessImageFileName, puProcessName, sizeof( buff ), NULL ) == STATUS_SUCCESS )
				{
					*( WCHAR* ) ( ( BYTE* ) buff + sizeof( buff ) - sizeof( WCHAR ) ) = 0;

					if ( puProcessName->Length + sizeof( WCHAR ) <= puProcessName->MaximumLength )
					{
						*( WCHAR* ) ( ( BYTE* ) puProcessName->Buffer + puProcessName->Length ) = 0;
					}

					WCHAR* pLastSlash = NULL;
					for ( WCHAR* pS = pwBuff;; pS++ )
					{
						WCHAR z = *pS;
						if ( !z )
						{
							if ( pLastSlash )
							{
								pwBuff = pLastSlash + 1;
							}

							break;
						}
						else if ( z == L'\\' )
						{
							pLastSlash = pS;
						}
					}

					if ( _wcsicmp( ImageName, pwBuff ) == 0 )
					{
						bResult = TRUE;
					}
				}

				ZwClose( hProcess );
			}
		}

		ObDereferenceObject( Process );
	}
	else {
		DBG_PRINT( "PsLookupProcessByProcessId failed with error code %d", status );
	}

	return bResult;
}