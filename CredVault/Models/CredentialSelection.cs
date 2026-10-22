namespace CredVault.Models;

/// <summary>
/// Rebuilds the credential rows after the store changes (add, edit, remove).
/// </summary>
public static class CredentialSelection
{
    /// <summary>
    /// One row per stored name, in store order. A row is checked only when a
    /// row of the same name was checked before; new names and an empty
    /// previous selection stay unchecked.
    /// </summary>
    public static List<CredentialEntry> Rebuild(IEnumerable<string> storedNames, IEnumerable<CredentialEntry> previous)
    {
        var checkedNames = previous
            .Where(c => c.IsSelected)
            .Select(c => c.Name)
            .ToHashSet(StringComparer.Ordinal);

        return storedNames
            .Select(name => new CredentialEntry { Name = name, IsSelected = checkedNames.Contains(name) })
            .ToList();
    }
}
