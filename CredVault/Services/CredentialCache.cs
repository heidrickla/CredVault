using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using CredVault.Native;

namespace CredVault.Services;

/// <summary>
/// Process-lifetime fingerprint cache backing the command-line secret
/// guardrail. It retains NO credential values in any form - not even
/// encrypted. Each value is reduced to an HMAC-SHA256 fingerprint keyed with
/// a random per-process key, plus its character length. Fingerprints are
/// one-way: a memory dump of this cache reveals nothing about the secrets.
///
/// Scanning: for every distinct cached length N, an N-char window slides
/// across the command line; each window is fingerprinted and compared in
/// constant time. A match means that credential's exact value occurs verbatim
/// in the command line.
///
/// Freshness: every scan re-enumerates the store (names + LastWritten
/// timestamps, no values) and re-fingerprints only entries whose timestamp
/// changed - so edits made OUTSIDE this app (cmdkey, control panel) are
/// picked up too. In-app writes additionally clear the cache via
/// CredentialManager.CredentialsChanged as belt-and-braces.
///
/// Plaintext exposure: a value is materialized only transiently while being
/// fingerprinted, in a buffer that is zeroed immediately after hashing.
/// </summary>
public static class CredentialCache
{
    private sealed record Entry(long LastWritten, int Length, byte[] Mac);

    // Random per-process key; never persisted, dies with the process.
    private static readonly byte[] HmacKey = RandomNumberGenerator.GetBytes(32);

    private static readonly Dictionary<string, Entry> _cache = new(StringComparer.Ordinal);
    private static readonly object _lock = new();
    private static bool _subscribed;

    /// <summary>
    /// Returns the name of the first stored credential whose value occurs
    /// verbatim in <paramref name="commandLine"/>, or null if none do.
    /// </summary>
    public static string? FindValueIn(string commandLine)
    {
        lock (_lock)
        {
            EnsureSubscribed();
            Reconcile();

            if (_cache.Count == 0 || commandLine.Length == 0)
                return null;

            Span<byte> windowMac = stackalloc byte[32];

            foreach (var lengthGroup in _cache.GroupBy(kv => kv.Value.Length))
            {
                var n = lengthGroup.Key;
                if (n == 0 || n > commandLine.Length)
                    continue;

                for (var i = 0; i + n <= commandLine.Length; i++)
                {
                    // UTF-16LE bytes of the window, no substring allocation.
                    var windowBytes = MemoryMarshal.AsBytes(commandLine.AsSpan(i, n));
                    HMACSHA256.HashData(HmacKey, windowBytes, windowMac);

                    foreach (var kv in lengthGroup)
                    {
                        if (CryptographicOperations.FixedTimeEquals(windowMac, kv.Value.Mac))
                            return kv.Key;
                    }
                }
            }

            return null;
        }
    }

    /// <summary>Drops every cached fingerprint.</summary>
    public static void InvalidateAll()
    {
        lock (_lock)
        {
            _cache.Clear();
        }
    }

    private static void EnsureSubscribed()
    {
        // Lazy: the cache is empty until first use, so no change can be
        // missed before this runs - the first scan reads current state.
        if (_subscribed)
            return;
        CredentialManager.CredentialsChanged += InvalidateAll;
        _subscribed = true;
    }

    // Bring the cache in line with the store: evict names that no longer
    // exist, (re-)fingerprint entries that are new or whose LastWritten
    // timestamp differs from what we cached.
    private static void Reconcile()
    {
        var current = CredentialManager.ListWithTimestamps();
        var names = new HashSet<string>(current.Select(c => c.Name), StringComparer.Ordinal);

        foreach (var stale in _cache.Keys.Where(k => !names.Contains(k)).ToList())
            _cache.Remove(stale);

        foreach (var (name, lastWritten) in current)
        {
            if (_cache.TryGetValue(name, out var existing) && existing.LastWritten == lastWritten)
                continue;

            if (CredentialManager.TryRead(name, out var secure) && secure is not null)
            {
                _cache[name] = new Entry(lastWritten, secure.Length, Fingerprint(secure));
                secure.Dispose();
            }
        }
    }

    private static byte[] Fingerprint(SecureString secure)
    {
        var ptr = Marshal.SecureStringToGlobalAllocUnicode(secure);
        try
        {
            var bytes = new byte[secure.Length * sizeof(char)];
            Marshal.Copy(ptr, bytes, 0, bytes.Length);
            var mac = HMACSHA256.HashData(HmacKey, bytes);
            CryptographicOperations.ZeroMemory(bytes);
            return mac;
        }
        finally
        {
            Marshal.ZeroFreeGlobalAllocUnicode(ptr);
        }
    }
}
