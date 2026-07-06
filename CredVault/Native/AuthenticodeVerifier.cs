using System.Runtime.InteropServices;

namespace CredVault.Native;

public enum SignatureStatus
{
    /// <summary>Embedded Authenticode signature present and valid.</summary>
    ValidSignature,

    /// <summary>No embedded signature (typical for dev tools, scripts,
    /// and catalog-signed Windows components like cmd.exe).</summary>
    NoEmbeddedSignature,

    /// <summary>Signature present but could not be validated (expired,
    /// untrusted root, ...). Allowed, but reported.</summary>
    NotValidated,

    /// <summary>Signature present and the file digest does NOT match -
    /// the file was modified after signing. Launch must be refused.</summary>
    TamperedSignature,
}

/// <summary>
/// Thin WinVerifyTrust (wintrust.dll) wrapper used by the launch pipeline.
///
/// Policy: only <see cref="SignatureStatus.TamperedSignature"/> (bad digest)
/// blocks a launch - it is the one unambiguous tamper signal. Absent or
/// unvalidatable signatures are permitted because most local dev tools are
/// unsigned; they are surfaced in the session log instead. Revocation is not
/// checked (offline-safe; no network calls during a launch).
/// </summary>
public static class AuthenticodeVerifier
{
    private static readonly Guid ActionGenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_REVOCATION_CHECK_NONE = 0x00000010;
    private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000;

    private const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);
    private const int TRUST_E_SUBJECT_FORM_UNKNOWN = unchecked((int)0x800B0003);
    private const int TRUST_E_BAD_DIGEST = unchecked((int)0x80096010);

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
    }

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, ref WINTRUST_DATA pWVTData);

    public static (SignatureStatus Status, int HResult) Verify(string filePath)
    {
        var pathPtr = Marshal.StringToCoTaskMemUni(filePath);
        var fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());

        try
        {
            var fileInfo = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                pcwszFilePath = pathPtr,
            };
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_NONE,
                dwUnionChoice = WTD_CHOICE_FILE,
                pFile = fileInfoPtr,
                dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL,
            };

            var hr = WinVerifyTrust((IntPtr)(-1), ActionGenericVerifyV2, ref data);

            var status = hr switch
            {
                0 => SignatureStatus.ValidSignature,
                TRUST_E_NOSIGNATURE or TRUST_E_SUBJECT_FORM_UNKNOWN => SignatureStatus.NoEmbeddedSignature,
                TRUST_E_BAD_DIGEST => SignatureStatus.TamperedSignature,
                _ => SignatureStatus.NotValidated,
            };

            return (status, hr);
        }
        finally
        {
            Marshal.FreeHGlobal(fileInfoPtr);
            Marshal.FreeCoTaskMem(pathPtr);
        }
    }
}
