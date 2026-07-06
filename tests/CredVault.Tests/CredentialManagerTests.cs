using CredVault.Native;
using static CredVault.Tests.TestSupport;

namespace CredVault.Tests;

public class CredentialManagerTests
{
    [Fact]
    public void Save_then_read_round_trips_the_value()
    {
        using var cred = NewCredentialName();
        const string value = "s3cr3t-value-should-never-leak";

        Assert.True(CredentialManager.Save(cred.Name, Secure(value)));

        Assert.True(CredentialManager.TryRead(cred.Name, out var read));
        Assert.NotNull(read);
        Assert.Equal(value, Reveal(read!));
        read!.Dispose();
    }

    [Fact]
    public void List_includes_saved_name_and_excludes_deleted_name()
    {
        using var cred = NewCredentialName();
        CredentialManager.Save(cred.Name, Secure("x"));

        Assert.Contains(cred.Name, CredentialManager.List());

        Assert.True(CredentialManager.Delete(cred.Name));
        Assert.DoesNotContain(cred.Name, CredentialManager.List());
    }

    [Fact]
    public void Save_with_same_name_overwrites_the_stored_value()
    {
        using var cred = NewCredentialName();
        CredentialManager.Save(cred.Name, Secure("original"));

        // This is what the UI's "Edit" does - overwrite in place, no delete.
        Assert.True(CredentialManager.Save(cred.Name, Secure("rotated-value-42")));

        Assert.True(CredentialManager.TryRead(cred.Name, out var read));
        Assert.Equal("rotated-value-42", Reveal(read!));
        read!.Dispose();
    }

    [Fact]
    public void Delete_is_idempotent()
    {
        using var cred = NewCredentialName();
        CredentialManager.Save(cred.Name, Secure("x"));

        Assert.True(CredentialManager.Delete(cred.Name));
        // Deleting something already gone is treated as success.
        Assert.True(CredentialManager.Delete(cred.Name));
    }

    [Fact]
    public void TryRead_returns_false_for_unknown_name()
    {
        using var cred = NewCredentialName(); // created only to guarantee absence
        Assert.False(CredentialManager.TryRead(cred.Name, out var read));
        Assert.Null(read);
    }
}
