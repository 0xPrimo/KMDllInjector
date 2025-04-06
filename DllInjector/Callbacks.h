#pragma once

#include "Utils.h"
#include "DrvTypes.h"
#include "Injector.h"
#include "Utils.h"

VOID OnProcessCreate( PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo );
VOID OnLoadImage( PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo );