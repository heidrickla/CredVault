using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace CredVault.Native;

/// <summary>
/// Thin wrapper over the Windows Credential Manager (advapi32.dll).
/// Secrets are encrypted at rest via DPAPI, tied to the current
/// Windows user profile - the same store Windows itself uses for
/// saved Wi-Fi and RDP passwords. This class never writes a plaintext
/// secret to disk, a log file, or the clipboard.
///
/// All entries are stored under the "CredVault:" target-name prefix
/// so this app only ever sees credentials it created itself.
/// </summary>
public static class CredentialManager
{
    private const uint CRED_TYPE_GENERIC = 1;
    private const uint CRED_PERSIST_LOCAL_MACHINE = 2;
    private const int ERROR_NOT_FOUND = 1168;
    private const string Prefix = "CredVault:";

    /// <summary>
    /// Raised after this app successfully creates, overwrites, or deletes a
    /// credential. Used to invalidate in-memory caches so they never serve a
    /// stale value for a change made through this app.
    /// </summary>
    public static event Action? CredentialsChanged;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CREDENTIAL
    {
        public uint Flags;
        public uint Type;
        public IntPtr TargetName;
        public IntPtr Comment;
        public long LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public IntPtr TargetAlias;
        public IntPtr UserName;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CredWriteW(ref CREDENTIAL credential, uint flags);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CredReadW(string target, uint type, int reservedFlag, out IntPtr credentialPtr);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CredDeleteW(string target, uint type, int flags);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CredEnumerateW(string? filter, uint flags, out uint count, out IntPtr credentialsPtr);

    [DllImport("advapi32.dll")]
    private static extern void CredFree(IntPtr buffer);

    public static bool Save(string name, SecureString secret)
    {
        var targetNamePtr = Marshal.StringToCoTaskMemUni(Prefix + name);
        var userNamePtr = Marshal.StringToCoTaskMemUni(Environment.UserName);

        // Marshal the secret straight from SecureString into an unmanaged
        // buffer passed to CredWrite - no intermediate managed string or
        // byte[] copy is ever created, and the buffer is explicitly zeroed.
        var blobPtr = Marshal.SecureStringToGlobalAllocUnicode(secret);

        try
        {
            var credential = new CREDENTIAL
            {
                Type = CRED_TYPE_GENERIC,
                TargetName = targetNamePtr,
                CredentialBlobSize = (uint)(secret.Length * sizeof(char)),
                CredentialBlob = blobPtr,
                Persist = CRED_PERSIST_LOCAL_MACHINE,
                UserName = userNamePtr
            };

            var ok = CredWriteW(ref credential, 0);
            if (ok)
                CredentialsChanged?.Invoke();
            return ok;
        }
        finally
        {
            Marshal.ZeroFreeGlobalAllocUnicode(blobPtr);
            Marshal.FreeCoTaskMem(targetNamePtr);
            Marshal.FreeCoTaskMem(userNamePtr);
        }
    }

    public static bool TryRead(string name, out SecureString? secret)
    {
        secret = null;

        if (!CredReadW(Prefix + name, CRED_TYPE_GENERIC, 0, out var credPtr))
            return false;

        try
        {
            var credential = Marshal.PtrToStructure<CREDENTIAL>(credPtr);

            // Defensive: an externally written credential may have a null or
            // empty blob; treat it as an empty secret instead of faulting.
            if (credential.CredentialBlob == IntPtr.Zero || credential.CredentialBlobSize == 0)
            {
                secret = new SecureString();
                secret.MakeReadOnly();
                return true;
            }

            // Clamp to whole UTF-16 chars in case an external writer stored
            // an odd byte count.
            var byteLen = (int)(credential.CredentialBlobSize & ~1u);
            var bytes = new byte[byteLen];
            Marshal.Copy(credential.CredentialBlob, bytes, 0, bytes.Length);

            var chars = Encoding.Unicode.GetChars(bytes);
            secret = new SecureString();
            foreach (var c in chars) secret.AppendChar(c);
            secret.MakeReadOnly();

            Array.Clear(bytes, 0, bytes.Length);
            Array.Clear(chars, 0, chars.Length);
            return true;
        }
        finally
        {
            CredFree(credPtr);
        }
    }

    public static bool Delete(string name)
    {
        if (CredDeleteW(Prefix + name, CRED_TYPE_GENERIC, 0))
        {
            CredentialsChanged?.Invoke();
            return true;
        }

        // Treat "already gone" as success.
        return Marshal.GetLastWin32Error() == ERROR_NOT_FOUND;
    }

    public static List<string> List() =>
        ListWithTimestamps().Select(e => e.Name).ToList();

    /// <summary>
    /// Enumerates CredVault credentials with the store's LastWritten
    /// timestamp (FILETIME). The timestamp lets callers detect writes made
    /// by other tools (cmdkey, the Credential Manager control panel, etc.)
    /// without reading any values.
    /// </summary>
    public static List<(string Name, long LastWritten)> ListWithTimestamps()
    {
        var results = new List<(string, long)>();

        if (!CredEnumerateW(Prefix + "*", 0, out var count, out var arrayPtr))
            return results;

        try
        {
            for (var i = 0; i < count; i++)
            {
                var entryPtr = Marshal.ReadIntPtr(arrayPtr, i * IntPtr.Size);
                var credential = Marshal.PtrToStructure<CREDENTIAL>(entryPtr);
                var fullName = Marshal.PtrToStringUni(credential.TargetName) ?? string.Empty;

                if (fullName.StartsWith(Prefix, StringComparison.Ordinal))
                    results.Add((fullName[Prefix.Length..], credential.LastWritten));
            }
        }
        finally
        {
            CredFree(arrayPtr);
        }

        return results;
    }
}
