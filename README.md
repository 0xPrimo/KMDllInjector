# About
KMDllInjector is a kernel-mode based DLL injector. The driver can be configured with `DllInjectorClient.exe` to use either `PsSetLoadImageNotifyRoutine` or `PsSetCreateProcessNotifyRoutineEx` to register a kernel callback.
Once the callback is triggered (image is loaded \ process created), it injects a DLL into the target user-mode process.
# How it works?
To inject a dll before process entrypoint is called the driver can use two techniques:

## PsSetCreateProcessNotifyRoutineEx + Shellcode Injection

This technique uses `PsSetCreateProcessNotifyRoutineEx` to register a callback that gets triggered whenever a new process is created.
Since `ntdll.dll` is loaded from kernel-mode, in the callback, we'll hook `Ntdll!LdrLoadDll` with a detour shellcode. 

The problem is that at this stage of process creation, the `PEB->Ldr` structure isn't initialized yet.

![LdrIsNull](https://github.com/user-attachments/assets/abe5f29e-565b-4c49-9b73-cbf61a38e8c1)

So how can we find base address of `ntdll.dll`?


The solution I came up with is since the `ntdll.dll` is mapped into the process virtual memory space, 
I can use `ntoskernel!ZwQueryVirtualMemory` to enumerate image mapped type of memory regions, check if the memory region base address contains a valid PE header, then parse the PE header to determine if it's a DLL.
```c
while ( TRUE ) {
  status = ZwQueryVirtualMemory( ZwCurrentProcess( ), baseAddress, MemoryBasicInformation, &memInfo, sizeof( memInfo ), &returnLength );
  if ( !NT_SUCCESS( status ) )
			break;

  // Check if this region is a mapped image
  if ( memInfo.Type == MEM_IMAGE ) {
    if ( IsDllModule( memInfo.BaseAddress ) ) {
      DBG_PRINT( "Ntdll: %p", memInfo.BaseAddress );
      *NtdllBase = memInfo.BaseAddress;
      return STATUS_SUCCESS;
    }
  }

  // Move to the next region
  baseAddress = ( PVOID ) ( ( ULONG_PTR ) memInfo.BaseAddress + memInfo.RegionSize );
}
```

After we found the base address of `ntdll.dll` of the target process we hook `Ntdll!LdrLoadDll` with a detour shellcode, the shellcode will do the following:
1. Restores the original prologue of LdrLoadDll (removing the hook),
2. Calls LdrLoadDll with the passed arguments.
3. Then loads our custom DLL into the process.

Instead of writing the shellcode in assembly, I used a trick I saw from [Rhydon1337: windows-kernel-dll-injector](https://github.com/Rhydon1337/windows-kernel-dll-injector/blob/main/DLLInjector/DLLInjector/dll_injection.cpp#L18) to use a function as a shellcode.
Since the function will be position-independent code, I disabled stack cookies, optimization, and Control Flow Guard (CFG).
I also used `#pragma code_seg(".text$")` to ensure that the functions is in the same order as in cpp file.
```c
#pragma optimize("", off)
#pragma code_seg(".text$A")
__declspec( safebuffers ) // disable stack cookies
// CFG can be disabled from Properties > C/C++ > Code Generation > Control Flow Guad > No
NTSTATUS HookLdrLoadDll( PWCHAR pwPathToFile, ULONG ulFlags, PUNICODE_STRING puModuleFileName, PHANDLE phModuleHandle )
{
	PHOOK_CONTEXT pContext = ( PHOOK_CONTEXT ) 0xBAADF00DBAADBEEF;
}
#pragma code_seg(".text$B")
DWORD HookLdrLoadDllEnd( ) {
	return 2;
}
#pragma optimize("", on)
```

The shellcode will need a context that will have saved copy of ldrloaddll prologue (use it to restore the `Ntdll!LdrLoadDll`)
and Ntdll exports (`NtProtectVirtualMemory`, `LdrLoadDLl`, `RtlInitUnicodeString`)

After context is initialized we scan for the pattern `0xBAADF00DBAADBEEF` and replace it with the address of the context.
```c
// Search for '0xBAADF00DBAADBEEF' pattern and replace it with the address to the context
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
```
The figure shows how the allocated memory in the target process looks like:
![image](https://github.com/user-attachments/assets/9e58b5dd-e27b-4f3b-9d5e-c670a1458e82)

### Demo 02

https://github.com/user-attachments/assets/c4f361ca-3235-4dae-96b7-6d12c2bb92da


## PsImageLoadNotify + APC Injection
`PsImageLoadNotify` is used to register kernel callback that get triggered whenever an image is loaded. 
Since we only want to inject the DLL into newly created user-mode processes, we'll apply a filter using the following if statement:
```c
if (
      // Exclude system images.
      !ImageInfo->SystemModeImage &&

      // Exclude images loaded remotely.
      ProcessId == PsGetCurrentProcessId( ) &&

      // Exclude image name that not end with kernel32.dll.
      (the first dll that is get loaded from user-mode on process creation is kernel32.dll)
      Utils::EndsWithUnicodeString( FullImageName, &uKernel32, TRUE ) &&

      // Exclude images that not get loaded via `LdrLoadDll`.
      // (This is checked by verifying if Teb->ArbitraryUserPointer == L"...\kernel32.dll".)
      Utils::IsLoadedByLdrLoadDll( &uKernel32 )
)
{
    // At this point, we're in a good position to inject the DLL
    // right after kernel32.dll has been loaded. 
}
```

`LdrInitializeThunk` is the first function executed in user-mode where process is in the creation steps. 
The last thing this function do is it calls `Ntdll!NtTestAlert` to free the APC queue.

This makes it a great opportunity to inject our DLL, so if we queue an APC before `Ntdll!NtTestAlert` is called, our code will be executed as part of the process's normal flow.
We can inject/queue APC from kernel-mode with	`KeInitializeApc` and `KeInsertQueueApc`.
```c
KeInitializeApc( apc, Thread, OriginalApcEnvironment, KernelAPC, NULL, APCCallbackCodeCave, UserMode, Arguments );
KeInsertQueueApc( apc, NULL, NULL, 0 );
```

### Demo 01
https://github.com/user-attachments/assets/f132bb18-3c9f-472b-878c-c820fe342472

# Credits
- [@outflank: Introducing Early Cascade Injection](https://www.outflank.nl/blog/2024/10/15/introducing-early-cascade-injection-from-windows-process-creation-to-stealthy-injection)
- [@Rhydon1337: windows-kernel-dll-injector](https://github.com/Rhydon1337/windows-kernel-dll-injector)
- [@dennisbabkin: DLL Injection playlist](https://www.youtube.com/watch?v=_k3njkNkvmI&list=PLo7Gwt6RpLEdF1cdS7rJ3AFv_Qusbs9hD)
- [@5pider: Modern shellcode implant design](https://5pider.net/blog/2024/01/27/modern-shellcode-implant-design)
