using System.Security;
using System.Windows;

namespace CredVault;

public partial class AddCredentialWindow : Window
{
    public string CredentialName { get; private set; } = string.Empty;
    public SecureString? Secret { get; private set; }

    private readonly bool _editMode;

    /// <summary>Add mode: blank dialog for a brand-new credential.</summary>
    public AddCredentialWindow()
    {
        InitializeComponent();
    }

    /// <summary>
    /// Edit mode: the name is fixed (it is the storage key) and shown
    /// read-only; saving overwrites the existing value via CredWrite.
    /// The current secret is never read back into the dialog - the user
    /// supplies a new value.
    /// </summary>
    public AddCredentialWindow(string existingName) : this()
    {
        _editMode = true;
        Title = "Edit credential";
        NameBox.Text = existingName;
        NameBox.IsReadOnly = true;
        NameBox.IsEnabled = false;
        SecretLabel.Text = "New secret value (replaces the stored one)";
        Loaded += (_, _) => SecretBox.Focus();
    }

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(NameBox.Text) || SecretBox.SecurePassword.Length == 0)
        {
            ShowError(_editMode
                ? "Enter a new secret value."
                : "Enter a name and a secret value.");
            return;
        }

        var name = NameBox.Text.Trim();

        // Guardrail: the name becomes an environment-variable name, so reject
        // anything that isn't a valid one (in edit mode the name is fixed and
        // already validated, so this only bites on add).
        if (!IsValidEnvVarName(name))
        {
            ShowError("Name must be a valid environment-variable name: " +
                      "no spaces, '=', or control characters.");
            return;
        }

        CredentialName = name;
        Secret = SecretBox.SecurePassword;
        Secret.MakeReadOnly();
        DialogResult = true;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
    }

    private static bool IsValidEnvVarName(string name)
    {
        // Windows allows most characters, but '=' is the name/value separator
        // and whitespace/control characters make a variable awkward or
        // impossible to reference reliably from a test script.
        foreach (var c in name)
        {
            if (c == '=' || char.IsWhiteSpace(c) || char.IsControl(c))
                return false;
        }
        return true;
    }

    private void ShowError(string message)
    {
        ErrorText.Text = message;
        ErrorText.Visibility = Visibility.Visible;
    }
}
