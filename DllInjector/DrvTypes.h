#pragma once

#include "Common.h"
#include <ntddk.h>
#include <wdm.h>

#define IOCTL_START_HOOKING CTL_CODE(0x8000, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_STOP_HOOKING CTL_CODE(0x8000, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define DRIVER_DEVICE_NAME L"\\Device\\DllInjector"
#define DRIVER_SYMBOLIC_LINK L"\\??\\DllInjector"

enum DRIVER_FLAGS
{
	flNone,
	flImageNotifySet,
	flImageNotifyUnset,

	flProcessNotifySet,
	flProcessNotifyUnset,
};

enum HOOK_TECHNIQUE
{
	APC_CALLBACK,
	TRAMPOLINE
};

typedef struct {
	HOOK_TECHNIQUE	Method;
	WCHAR			ProcessToInject[ ( MAX_PATH - 1 ) * 2 ];
	WCHAR			PathToDll[ ( MAX_PATH - 1 ) * 2 ];
} REQUEST, * PREQUEST;

NTSTATUS	DriverCreateClose( PDEVICE_OBJECT DriverObject, PIRP Irp );
NTSTATUS	DriverDeviceControl( PDEVICE_OBJECT DriverObject, PIRP Irp );
VOID		DriverUnload( PDRIVER_OBJECT DriverObject );
VOID		OnLoadImage( PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo );

extern DRIVER_FLAGS		g_Flags;
extern WCHAR			g_ProcessToInject[ MAX_PATH * 2 ];
extern WCHAR			g_DllToInject[ MAX_PATH * 2 ];