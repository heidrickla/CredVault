using System.ComponentModel;

namespace CredVault.Models;

/// <summary>
/// Represents a credential name shown in the UI. Never carries the
/// secret value itself - that stays in Windows Credential Manager
/// and is only pulled out, briefly, at launch time.
/// </summary>
public class CredentialEntry : INotifyPropertyChanged
{
    private bool _isSelected = true;

    public string Name { get; set; } = string.Empty;

    public bool IsSelected
    {
        get => _isSelected;
        set
        {
            if (_isSelected == value) return;
            _isSelected = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsSelected)));
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
}
