using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Windows;
using CredVault.Models;
using CredVault.Native;
using CredVault.Services;

namespace CredVault;

public partial class MainWindow : Window
{
    private readonly ObservableCollection<CredentialEntry> _credentials = new();
    private readonly AppSettings _settings;
    private Process? _runningProcess;

    public MainWindow()
    {
        InitializeComponent();
        CredentialList.ItemsSource = _credentials;

        _settings = AppSettings.Load();
        CommandBox.Text = string.IsNullOrWhiteSpace(_settings.LastCommand)
            ? @"pwsh -File .\run-auth-tests.ps1"
            : _settings.LastCommand;

        ReloadCredentials();
        UpdateLaunchEnabled();
    }

    private void ReloadCredentials()
    {
        // Preserve which names were checked across a reload so an edit/remove
        // doesn't silently reset the user's launch selection.
        var previouslySelected = _credentials
            .Where(c => c.IsSelected)
            .Select(c => c.Name)
            .ToHashSet(StringComparer.Ordinal);

        _credentials.Clear();
        foreach (var name in CredentialManager.List())
            _credentials.Add(new CredentialEntry
            {
                Name = name,
                IsSelected = previouslySelected.Count == 0 || previouslySelected.Contains(name)
            });
    }

    private void AddCredential_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new AddCredentialWindow { Owner = this };
        if (dialog.ShowDialog() == true && dialog.Secret is not null)
        {
            if (!CredentialManager.Save(dialog.CredentialName, dialog.Secret))
                AppendLog($"failed to save credential '{dialog.CredentialName}'");
            dialog.Secret.Dispose(); // zero the unmanaged buffer promptly
            ReloadCredentials();
        }
    }

    private void EditCredential_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { Tag: string name })
            return;

        // Edit mode overwrites the stored value under the same name via
        // CredWrite - no delete-then-recreate. The existing secret is never
        // read back into the UI; the user types a fresh value.
        var dialog = new AddCredentialWindow(name) { Owner = this };
        if (dialog.ShowDialog() == true && dialog.Secret is not null)
        {
            if (!CredentialManager.Save(dialog.CredentialName, dialog.Secret))
                AppendLog($"failed to update credential '{name}'");
            else
                AppendLog($"updated credential '{name}'");
            dialog.Secret.Dispose(); // zero the unmanaged buffer promptly

            // Re-read from Credential Manager so the list reflects the store.
            ReloadCredentials();
        }
    }

    private void RemoveCredential_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: string name })
        {
            var deleted = CredentialManager.Delete(name);

            // Re-read the list from Credential Manager rather than removing the
            // row locally, so the UI always mirrors what is actually stored.
            ReloadCredentials();

            AppendLog(deleted
                ? $"removed credential '{name}'"
                : $"could not remove credential '{name}'");
        }
    }

    private void CommandBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        UpdateLaunchEnabled();
    }

    private void UpdateLaunchEnabled()
    {
        // Only gate on the command box; Launch stays disabled while a
        // process is already running (re-enabled on exit/cancel).
        var canLaunch = _runningProcess is null or { HasExited: true }
                        && !string.IsNullOrWhiteSpace(CommandBox.Text);
        LaunchButton.IsEnabled = canLaunch;
    }

    private void Launch_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(CommandBox.Text))
            return;

        var selected = new List<string>();
        foreach (var entry in _credentials)
            if (entry.IsSelected) selected.Add(entry.Name);

        LogBox.Clear();
        ClearError();
        LaunchButton.IsEnabled = false;
        CancelButton.IsEnabled = true;

        try
        {
            // Phase 1: resolve, pin, hash, and signature-check the target -
            // no secret has been read yet at this point.
            using var plan = ProcessLauncher.Prepare(CommandBox.Text);

            // Change tripwire: if this executable hashed differently the
            // last time it was launched, confirm before injecting anything.
            if (!ConfirmIfExecutableChanged(plan))
            {
                AppendLog($"launch aborted by user: executable changed since last launch");
                ResetAfterFailedLaunch();
                return;
            }

            // Phase 2: secrets are read and injected only now.
            var process = ProcessLauncher.Launch(plan, selected, AppendLog);
            _runningProcess = process;
            process.Exited += (_, _) => Dispatcher.Invoke(() =>
            {
                // Capture the specific process this handler belongs to rather
                // than the (possibly reassigned) field.
                AppendLog($"process exited, code {process.ExitCode}");
                CancelButton.IsEnabled = false;
                UpdateLaunchEnabled();
            });

            // Persist the command line only after it cleared the secret check
            // and actually started - so a rejected command is never written.
            RememberExecutable(plan);
            PersistCommand();
        }
        catch (SecretInCommandLineException ex)
        {
            // Guardrail: a stored secret's value was typed into the command.
            // Refuse, do NOT persist the command, and tell the user to
            // reference it by name. The message carries only the name.
            ShowError($"The command line contains the stored value of '{ex.CredentialName}'. " +
                      "Remove it and reference the credential by its name instead - " +
                      "it is injected as an environment variable.");
            ResetAfterFailedLaunch();
        }
        catch (TamperedExecutableException)
        {
            // The image is signed but its digest no longer matches: it was
            // modified after signing. Never inject into it.
            ShowError("The target executable failed its signature integrity check - " +
                      "it was modified after being signed. Launch refused.");
            ResetAfterFailedLaunch();
        }
        catch (Win32Exception ex)
        {
            // Bad path, access denied, not a valid executable, etc. Surface a
            // friendly inline error - not just a logged exception string.
            // The command cleared the secret check before Start(), so it is
            // safe to remember for next time.
            ShowError(DescribeLaunchFailure(ex));
            PersistCommand();
            ResetAfterFailedLaunch();
        }
        catch (Exception)
        {
            // Deliberately do not echo ex.Message: it can contain arguments
            // from the command line. Credential values are never placed on the
            // command line (the guardrail above enforces that), but we keep the
            // surface minimal regardless.
            ShowError("Could not start the process. Check the command and try again.");
            ResetAfterFailedLaunch();
        }
    }

    private void PersistCommand()
    {
        // The command text is not a secret (the launcher refuses to run a
        // command that contains a stored secret value), so it is safe to save.
        _settings.LastCommand = CommandBox.Text;
        _settings.Save();
    }

    /// <summary>
    /// Returns false when the executable at this path hashed differently on a
    /// previous launch and the user declines to proceed. First-time paths are
    /// allowed silently (their hash is recorded after a successful start).
    /// </summary>
    private bool ConfirmIfExecutableChanged(LaunchPlan plan)
    {
        var key = plan.ResolvedPath.ToLowerInvariant();
        if (!_settings.KnownExecutableHashes.TryGetValue(key, out var known) || known == plan.Sha256)
            return true;

        var choice = MessageBox.Show(this,
            "The executable has changed since you last launched it:\n\n" +
            $"{plan.ResolvedPath}\n\n" +
            "If you didn't update this program yourself, it may have been " +
            "replaced by something malicious. Launch it and inject the " +
            "selected credentials anyway?",
            "CredVault - executable changed",
            MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);

        return choice == MessageBoxResult.Yes;
    }

    private void RememberExecutable(LaunchPlan plan)
    {
        _settings.KnownExecutableHashes[plan.ResolvedPath.ToLowerInvariant()] = plan.Sha256;
        // Persisted by the PersistCommand() call that follows a launch.
    }

    private void ResetAfterFailedLaunch()
    {
        _runningProcess = null;
        CancelButton.IsEnabled = false;
        UpdateLaunchEnabled();
    }

    private static string DescribeLaunchFailure(Win32Exception ex) => ex.NativeErrorCode switch
    {
        2 => "Command not found. Check the path or executable name.",
        3 => "Path not found. Check the directory in the command.",
        5 => "Access denied. You don't have permission to run that command.",
        193 => "That file isn't a valid executable.",
        _ => "Could not start the process. Check the command and try again."
    };

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        var process = _runningProcess;
        if (process is { HasExited: false })
        {
            try
            {
                // Kill the whole tree so a shell/wrapper's child processes
                // (e.g. a script it spawned) are terminated too, not just the
                // top-level process.
                process.Kill(entireProcessTree: true);
                process.WaitForExit(5000);
                AppendLog("session cancelled by user (process tree terminated)");
            }
            catch (Exception)
            {
                // The process may have exited on its own between the check and
                // the kill; that's fine.
                AppendLog("session cancelled by user");
            }
        }

        CancelButton.IsEnabled = false;
        UpdateLaunchEnabled();
    }

    private void AppendLog(string line)
    {
        Dispatcher.Invoke(() =>
        {
            LogBox.AppendText($"{DateTime.Now:HH:mm:ss}  {line}\n");
            LogBox.ScrollToEnd();
        });
    }

    private void ShowError(string message)
    {
        ErrorText.Text = message;
        ErrorText.Visibility = Visibility.Visible;
    }

    private void ClearError()
    {
        ErrorText.Text = string.Empty;
        ErrorText.Visibility = Visibility.Collapsed;
    }

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        WindowTheming.ApplyDarkTitleBar(this);
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        // Intentionally does NOT persist the current command box text: only a
        // command that has passed the secret-in-command-line check and been
        // launched is saved (via PersistCommand). This prevents an unlaunched
        // command containing a typed-in secret from being written to disk on
        // exit. "Last used" therefore means "last launched".
        base.OnClosing(e);
    }
}
