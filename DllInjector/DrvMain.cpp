// DrvMain.cpp 

#include "DrvTypes.h"
#include "Callbacks.h"
#include "Injector.h"
#include "Utils.h"

DRIVER_FLAGS	g_Flags = DRIVER_FLAGS::flNone;
WCHAR			g_ProcessToInject[ MAX_PATH * 2 ];
WCHAR			g_DllToInject[ MAX_PATH * 2 ];

/**
 * @brief Entry point for the driver.
 *
 * @param DriverObject A pointer to the DRIVER_OBJECT structure representing this driver.
 * @param RegistryPath A pointer to a UNICODE_STRING containing the registry path
 *
 * @return STATUS_SUCCESS if the driver initialized successfully.
 *         Otherwise, an appropriate NTSTATUS error code.
 */
extern "C"
NTSTATUS NTAPI DriverEntry( PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath )
{
	UNREFERENCED_PARAMETER( RegistryPath );

	NTSTATUS		status = STATUS_SUCCESS;
	PDEVICE_OBJECT	DeviceObject = NULL;

	// Setting up the device object.
	UNICODE_STRING DeviceName = RTL_CONSTANT_STRING( DRIVER_DEVICE_NAME );
	UNICODE_STRING SymbolicLink = RTL_CONSTANT_STRING( DRIVER_SYMBOLIC_LINK );

	DriverObject->DriverUnload = DriverUnload;
	DriverObject->MajorFunction[ IRP_MJ_CREATE ] = DriverObject->MajorFunction[ IRP_MJ_CLOSE ] = DriverCreateClose;
	DriverObject->MajorFunction[ IRP_MJ_DEVICE_CONTROL ] = DriverDeviceControl;

	// Creating device.
	status = IoCreateDevice( DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject );
	if ( !NT_SUCCESS( status ) ) {
		DBG_PRINT( "Failed to create device: (0x%08X)\n", status );
		return status;
	}

	// Creating symbolic link.
	status = IoCreateSymbolicLink( &SymbolicLink, &DeviceName );
	if ( !NT_SUCCESS( status ) ) {
		DBG_PRINT( "Failed to create symbolic link: (0x%08X)\n", status );
		IoDeleteDevice( DeviceObject );
		return status;
	}

	DBG_PRINT( "Driver Loaded" );
	return STATUS_SUCCESS;
}

/**
 * @brief Handles I/O control requests (IOCTLs) for the driver.
 *
 * @param DriverObject	A pointer to the DEVICE_OBJECT representing the driver's device.
 * @param Irp			A pointer to the I/O request packet (IRP) containing the details of the request.
 *
 * @return An NTSTATUS code indicating success or failure of the operation.
 */
NTSTATUS DriverDeviceControl( PDEVICE_OBJECT DriverObject, PIRP Irp ) {
	UNREFERENCED_PARAMETER( DriverObject );

	NTSTATUS status = STATUS_SUCCESS;
	SIZE_T len = 0;
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation( Irp );

	DBG_PRINT( "DriverDeviceControl Called" );

	switch ( stack->Parameters.DeviceIoControl.IoControlCode )
	{
		case IOCTL_START_HOOKING:
		{
			ULONG size = stack->Parameters.DeviceIoControl.InputBufferLength;
			PREQUEST data = ( PREQUEST ) Irp->AssociatedIrp.SystemBuffer;

			if ( g_Flags != DRIVER_FLAGS::flImageNotifySet && g_Flags != DRIVER_FLAGS::flProcessNotifySet )
			{
				wcscpy( g_DllToInject, data->PathToDll );
				wcscpy( g_ProcessToInject, data->ProcessToInject );
				if ( data->Method == HOOK_TECHNIQUE::APC_CALLBACK )
				{
					status = PsSetLoadImageNotifyRoutine( OnLoadImage );
					if ( !NT_SUCCESS( status ) )
						DBG_PRINT( "PsSetLoadImageNotifyRoutine failed with error code %d", status );
					
					g_Flags = DRIVER_FLAGS::flImageNotifySet;
				}
				else if ( data->Method == HOOK_TECHNIQUE::TRAMPOLINE )
				{
					status = PsSetCreateProcessNotifyRoutineEx( OnProcessCreate, FALSE );
					if ( !NT_SUCCESS( status ) )
						DBG_PRINT( "PsSetCreateProcessNotifyRoutineEx failed with error code %d", status );
				
					g_Flags = DRIVER_FLAGS::flProcessNotifySet;
				}
				else
				{
					status = STATUS_INVALID_PARAMETER;
					DBG_PRINT( "Invalid Hooking Technique" );
				}
			}
			else {
				status = STATUS_DEVICE_BUSY;
				DBG_PRINT( "Callback already registered" );
			}

			len += size;
			break;
		}
		case IOCTL_STOP_HOOKING:
		{
			RtlZeroMemory( g_DllToInject, sizeof( g_DllToInject ) );
			RtlZeroMemory( g_ProcessToInject, sizeof( g_ProcessToInject ) );

			if ( g_Flags == DRIVER_FLAGS::flImageNotifySet )
			{
				status = PsRemoveLoadImageNotifyRoutine( OnLoadImage );
				if ( !NT_SUCCESS( status ) )
					DBG_PRINT( "PsRemoveLoadImageNotifyRoutine failed with code %d", status );
				else
					g_Flags = DRIVER_FLAGS::flImageNotifyUnset;
			} 
			else if ( g_Flags == DRIVER_FLAGS::flProcessNotifySet )
			{
				status = PsSetCreateProcessNotifyRoutineEx( OnProcessCreate, TRUE );
				if ( !NT_SUCCESS( status ) )
					DBG_PRINT( "PsSetCreateProcessNotifyRoutineEx failed with code %d", status );
				else
					g_Flags = DRIVER_FLAGS::flProcessNotifyUnset;
			}
			else {
				DBG_PRINT( "No callback registered" );
				status = STATUS_INVALID_DEVICE_STATE;
			}

			break;
		}
		default:
			status = STATUS_INVALID_DEVICE_REQUEST;
			break;
	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = len;
	IoCompleteRequest( Irp, IO_NO_INCREMENT );
	return status;
}

/**
 * @brief Handles create and close requests for the driver.
 *
 * @param DriverObject	A pointer to the DEVICE_OBJECT representing the driver's device.
 * @param Irp			A pointer to the I/O request packet (IRP) containing the request details.
 *
 * @return An NTSTATUS code indicating success or failure of the operation.
 */
NTSTATUS DriverCreateClose( PDEVICE_OBJECT DriverObject, PIRP Irp ) {
	UNREFERENCED_PARAMETER( DriverObject );

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest( Irp, IO_NO_INCREMENT );
	return STATUS_SUCCESS;
}

/**
 * @brief Unloads the driver and cleans up resources.
 *
 * @param DriverObject A pointer to the DRIVER_OBJECT representing this driver.
 */
VOID DriverUnload( PDRIVER_OBJECT DriverObject )
{
	UNREFERENCED_PARAMETER( DriverObject );
	NTSTATUS		status = STATUS_SUCCESS;
	UNICODE_STRING	SymbolicLink = RTL_CONSTANT_STRING( DRIVER_SYMBOLIC_LINK );

	IoDeleteSymbolicLink( &SymbolicLink );
	IoDeleteDevice( DriverObject->DeviceObject );

	if ( g_Flags == DRIVER_FLAGS::flImageNotifySet )
	{
		status = PsRemoveLoadImageNotifyRoutine( OnLoadImage );
		if ( !NT_SUCCESS( status ) )
			DBG_PRINT( "PsRemoveLoadImageNotifyRoutine failed with code %d", status );
	}

	if ( g_Flags == DRIVER_FLAGS::flProcessNotifySet )
	{
		status = PsSetCreateProcessNotifyRoutineEx( OnProcessCreate, TRUE );
		if ( !NT_SUCCESS( status ) )
			DBG_PRINT( "PsSetCreateProcessNotifyRoutineEx failed with code %d", status );
	}

	DBG_PRINT( "Driver Unload" );
}