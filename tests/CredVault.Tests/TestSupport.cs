using System.Runtime.InteropServices;
using System.Security;
using CredVault.Native;

// These tests exercise the real Windows Credential Manager and spawn real
// child processes, so they share machine-global state (credential store,
// running process list). Run them sequentially to keep them deterministic.
[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace CredVault.Tests;

internal static class TestSupport
{
    /// <summary>Builds a read-only SecureString from a plain string.</summary>
    public static SecureString Secure(string value)
    {
        var s = new SecureString();
        foreach (var c in value) s.AppendChar(c);
        s.MakeReadOnly();
        return s;
    }

    /// <summary>
    /// Reads a SecureString back to a plain string for assertions only.
    /// Test-only helper - production code never does this.
    /// </summary>
    public static string Reveal(SecureString secure)
    {
        var ptr = Marshal.SecureStringToGlobalAllocUnicode(secure);
        try
        {
            return Marshal.PtrToStringUni(ptr) ?? string.Empty;
        }
        finally
        {
            Marshal.ZeroFreeGlobalAllocUnicode(ptr);
        }
    }

    /// <summary>A unique CredVault credential name that deletes itself on dispose.</summary>
    public static TempCredential NewCredentialName() =>
        new($"CVTEST_{Guid.NewGuid():N}");

    internal sealed class TempCredential : IDisposable
    {
        public string Name { get; }

        public TempCredential(string name)
        {
            Name = name;
            CredentialManager.Delete(name); // ensure clean slate
        }

        public void Dispose() => CredentialManager.Delete(Name);
    }
}
