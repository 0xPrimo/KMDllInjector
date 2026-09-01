# About
KMDllInjector is a kernel-mode based DLL injector. The driver can be configured with `DllInjectorClient.exe` to use either `PsSetLoadImageNotifyRoutine` or `PsSetCreateProcessNotifyRoutineEx` to register a kernel callback.
Once the callback is triggered (image is loaded \ process created), it injects a DLL into the target user-mode process.
- Technical details: https://0xprimo.github.io/projects/kmdllinjector/
