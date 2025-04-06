#pragma once

#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#include <iostream>
#include <string>
#include <shlwapi.h>

#pragma comment(lib, "Shlwapi.lib") // Link Shlwapi.lib

#define IOCTL_START_HOOKING CTL_CODE(0x8000, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_STOP_HOOKING CTL_CODE(0x8000, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define DRIVER_NAME L"\\\\.\\DllInjector"

enum HOOK_TECHNIQUE
{
	APC_CALLBACK,
	TRAMPOLINE
};

typedef struct {
	HOOK_TECHNIQUE	Technique;
	WCHAR			ProcessToInject[ ( MAX_PATH - 1 ) * 2 ];
	WCHAR			PathToDll[ ( MAX_PATH - 1 ) * 2 ];
} REQUEST, * PREQUEST;