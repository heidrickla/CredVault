using System.Runtime.InteropServices;
using System.Security;
using CredVault.Native;

namespace CredVault.Services;

/// <summary>
/// Process-lifetime cache of stored credential values, held as
/// <see cref="SecureString"/> (encrypted in memory on Windows) so plaintext is
/// only ever materialized momentarily during a scan. It lets the command-line
/// secret guardrail check every stored credential without a Credential Manager
/// (LSASS) round-trip on each launch.
///
/// SECURITY:
///  - Values are cached encrypted (SecureString), never as plaintext, and are
///    never logged or persisted.
///  - The cache is fully invalidated whenever this app creates, overwrites, or
///    deletes a credential (via <see cref="CredentialManager.CredentialsChanged"/>),
///    and every scan reconciles names against the store, so in-app additions,
///    edits, and removals are always reflected.
///  - Residual gap: a credential value edited *outside* this app while it is
///    running would leave a stale cached value scanned until the next
///    invalidation. In-app edits are safe; the store is per-user either way.
/// </summary>
public static class CredentialCache
{
    private static readonly Dictionary<string, SecureString> _cache = new(StringComparer.Ordinal);
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

            foreach (var (name, secure) in _cache)
            {
                var ptr = Marshal.SecureStringToGlobalAllocUnicode(secure);
                try
                {
                    var plain = Marshal.PtrToStringUni(ptr);
                    if (!string.IsNullOrEmpty(plain) &&
                        commandLine.Contains(plain, StringComparison.Ordinal))
                        return name;
                }
                finally
                {
                    Marshal.ZeroFreeGlobalAllocUnicode(ptr);
                }
            }

            return null;
        }
    }

    /// <summary>Disposes and drops every cached value.</summary>
    public static void InvalidateAll()
    {
        lock (_lock)
        {
            foreach (var secure in _cache.Values)
                secure.Dispose();
            _cache.Clear();
        }
    }

    private static void EnsureSubscribed()
    {
        // Lazy: the cache is empty until first use, so there is nothing stale
        // to miss before this runs, and the first scan reads current state.
        if (_subscribed)
            return;
        CredentialManager.CredentialsChanged += InvalidateAll;
        _subscribed = true;
    }

    // Bring the cache in line with the current set of stored names: evict
    // entries that no longer exist and read in any that are missing.
    private static void Reconcile()
    {
        var names = CredentialManager.List();
        var nameSet = new HashSet<string>(names, StringComparer.Ordinal);

        foreach (var stale in _cache.Keys.Where(k => !nameSet.Contains(k)).ToList())
        {
            _cache[stale].Dispose();
            _cache.Remove(stale);
        }

        foreach (var name in names)
        {
            if (_cache.ContainsKey(name))
                continue;
            if (CredentialManager.TryRead(name, out var secure) && secure is not null)
                _cache[name] = secure;
        }
    }
}
