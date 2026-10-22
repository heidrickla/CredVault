using CredVault.Models;

namespace CredVault.Tests;

public class CredentialSelectionTests
{
    private static CredentialEntry Row(string name, bool selected) => new() { Name = name, IsSelected = selected };

    private static string[] Checked(IEnumerable<CredentialEntry> rows) =>
        rows.Where(r => r.IsSelected).Select(r => r.Name).ToArray();

    [Fact]
    public void A_new_row_starts_unchecked()
    {
        Assert.False(new CredentialEntry().IsSelected);
    }

    [Fact]
    public void First_load_checks_nothing()
    {
        var rows = CredentialSelection.Rebuild(new[] { "A", "B" }, Array.Empty<CredentialEntry>());

        Assert.Equal(new[] { "A", "B" }, rows.Select(r => r.Name));
        Assert.Empty(Checked(rows));
    }

    [Fact]
    public void An_empty_selection_stays_empty_after_add_edit_or_remove()
    {
        var previous = new[] { Row("A", false), Row("B", false), Row("C", false) };

        Assert.Empty(Checked(CredentialSelection.Rebuild(new[] { "A", "B", "C", "D" }, previous))); // add
        Assert.Empty(Checked(CredentialSelection.Rebuild(new[] { "A", "B", "C" }, previous)));      // edit
        Assert.Empty(Checked(CredentialSelection.Rebuild(new[] { "A", "C" }, previous)));           // remove
    }

    [Fact]
    public void Checked_rows_keep_their_check_and_an_added_row_stays_unchecked()
    {
        var previous = new[] { Row("A", true), Row("B", false), Row("C", true) };

        var rows = CredentialSelection.Rebuild(new[] { "A", "B", "D" }, previous);

        Assert.Equal(new[] { "A" }, Checked(rows));
        Assert.Equal(new[] { "A", "B", "D" }, rows.Select(r => r.Name));
    }
}
