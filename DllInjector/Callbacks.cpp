#include "Callbacks.h"

/**
 * @brief Callback function triggered when a process is created.
 *
 * @param Process		A pointer to the EPROCESS structure of the newly created process.
 * @param ProcessId		The process identifier (PID) of the newly created process.
 * @param CreateInfo	A pointer to a PS_CREATE_NOTIFY_INFO structure containing
 *						additional information about the process creation.
 */
VOID OnProcessCreate( PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo )
{
	UNREFERENCED_PARAMETER( Process );

	UNICODE_STRING uProcessName = { 0 };

	if ( !CreateInfo || !CreateInfo->FileOpenNameAvailable ) {
		return;
	}

	RtlInitUnicodeString( &uProcessName, g_ProcessToInject );

	if ( Utils::EndsWithUnicodeString( ( PUNICODE_STRING ) CreateInfo->ImageFileName, &uProcessName, TRUE ) )
	{
		DBG_PRINT( "New process created: %wZ (PID: %d)", CreateInfo->ImageFileName, ( ULONG ) ( ULONG_PTR ) ProcessId );
	
		if ( Injector::InjectDllHook( Process, g_DllToInject ) == FALSE )
			DBG_PRINT( "InjectDllHook Failed" );
	}
}

/**
 * @brief Callback function triggered when an image is loaded.
 *
 * @param FullImageName A pointer to a UNICODE_STRING containing the full path of the loaded image.
 * @param ProcessId		The process identifier (PID) of the process into which the image is being loaded.
 * @param ImageInfo		A pointer to an IMAGE_INFO structure containing details about the loaded image.
 */
VOID OnLoadImage( PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo )
{
	UNREFERENCED_PARAMETER( FullImageName );
	UNREFERENCED_PARAMETER( ProcessId );
	UNREFERENCED_PARAMETER( ImageInfo );

	ASSERT( FullImageName );
	ASSERT( ImageInfo );

	UNICODE_STRING	DllName = { 0 };
	//NTSTATUS		status = 0;

	RtlInitUnicodeString( &DllName, L"\\kernel32.dll" );

	if ( !ImageInfo->SystemModeImage &&
		 ProcessId == PsGetCurrentProcessId( ) &&
		 Utils::EndsWithUnicodeString( FullImageName, &DllName, TRUE ) &&
		 Utils::IsLoadedByLdrLoadDll( &DllName )
		 && Utils::IsSpecificProcessW( ProcessId, g_ProcessToInject, FALSE )
		 )
	{
		DBG_PRINT( "Image load for PID=%u: %wZ", ( ULONG ) ( ULONG_PTR ) ProcessId, FullImageName );
		
		if ( Injector::InjectDllAPC( ProcessId, g_DllToInject ) == FALSE )
			DBG_PRINT( "InjectDllAPC Failed" );
	}
}
