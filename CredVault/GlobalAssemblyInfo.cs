using System.Runtime.InteropServices;

// Security hardening: resolve every P/Invoke native library (advapi32.dll,
// dwmapi.dll) exclusively from the Windows System32 directory, never from the
// application directory. This prevents DLL search-order hijacking, where a
// malicious DLL planted next to the executable (e.g. a fake dwmapi.dll, which
// is not a protected KnownDLL) would otherwise be loaded in place of the real
// system library.
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
