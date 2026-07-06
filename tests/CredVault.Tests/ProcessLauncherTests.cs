using System.ComponentModel;
using System.Diagnostics;
using CredVault.Native;
using CredVault.Services;
using static CredVault.Tests.TestSupport;

namespace CredVault.Tests;

public class ProcessLauncherTests
{
    private const string SecretValue = "s3cr3t-value-should-never-leak";

    /// <summary>Runs a command to completion, returning every logged line.</summary>
    private static List<string> RunAndCollect(string commandLine, params string[] names)
    {
        var log = new List<string>();
        var process = ProcessLauncher.Launch(commandLine, names, line =>
        {
            lock (log) log.Add(line);
        });
        process.WaitForExit(10_000);
        Thread.Sleep(300); // let trailing async output drain
        lock (log) return new List<string>(log);
    }

    [Fact]
    public void Injects_selected_credential_and_logs_name_only()
    {
        using var cred = NewCredentialName();
        CredentialManager.Save(cred.Name, Secure(SecretValue));

        var log = RunAndCollect(
            $"cmd /c \"if defined {cred.Name} (echo INJECTED) else (echo MISSING)\"",
            cred.Name);

        Assert.Contains("INJECTED", log);
        Assert.Contains(log, l => l.Contains(cred.Name) && l.Contains("value hidden"));
        Assert.DoesNotContain(log, l => l.Contains(SecretValue));
    }

    [Fact]
    public void Guardrail_redacts_injected_value_from_child_output()
    {
        using var cred = NewCredentialName();
        CredentialManager.Save(cred.Name, Secure(SecretValue));

        // Child deliberately echoes its own secret env var - the classic leak.
        var log = RunAndCollect($"cmd /c echo the secret is %{cred.Name}%", cred.Name);

        Assert.DoesNotContain(log, l => l.Contains(SecretValue));
        Assert.Contains(log, l => l.Contains("«redacted»"));
    }

    [Fact]
    public void Guardrail_rejects_secret_value_on_the_command_line()
    {
        using var cred = NewCredentialName();
        CredentialManager.Save(cred.Name, Secure(SecretValue));

        // User pastes the actual value onto the command line instead of the name.
        var ex = Assert.Throws<SecretInCommandLineException>(() =>
            ProcessLauncher.Launch($"cmd /c echo {SecretValue}", new[] { cred.Name }, _ => { }));

        // The exception identifies the credential but never carries the value.
        Assert.Equal(cred.Name, ex.CredentialName);
        Assert.DoesNotContain(SecretValue, ex.Message);
    }

    [Fact]
    public void Guardrail_rejects_value_of_an_unselected_credential_on_the_command_line()
    {
        using var cred = NewCredentialName();
        CredentialManager.Save(cred.Name, Secure(SecretValue));

        // The credential's value is on the command line but the credential is
        // NOT passed as selected - it must still be caught (all stored
        // credentials are scanned).
        var ex = Assert.Throws<SecretInCommandLineException>(() =>
            ProcessLauncher.Launch($"cmd /c echo {SecretValue}", Array.Empty<string>(), _ => { }));

        Assert.Equal(cred.Name, ex.CredentialName);
        Assert.DoesNotContain(SecretValue, ex.Message);
    }

    [Fact]
    public void Missing_executable_throws_file_not_found_Win32Exception()
    {
        var ex = Assert.Throws<Win32Exception>(() =>
            ProcessLauncher.Launch(@"C:\definitely\not\here\nope.exe", Array.Empty<string>(), _ => { }));

        Assert.Equal(2, ex.NativeErrorCode); // ERROR_FILE_NOT_FOUND
    }

    [Fact]
    public void Cancel_kills_the_entire_process_tree()
    {
        // Parent cmd spawns a long-lived grandchild (ping loop). Killing the
        // tree must terminate the grandchild too, not just the top process.
        var parent = ProcessLauncher.Launch(
            "cmd /c \"start /b ping -n 30 127.0.0.1 >nul & ping -n 30 127.0.0.1 >nul\"",
            Array.Empty<string>(),
            _ => { });

        Thread.Sleep(1500);
        int pingsBefore = Process.GetProcessesByName("PING").Length;

        parent.Kill(entireProcessTree: true);
        parent.WaitForExit(5000);
        Thread.Sleep(1500);
        int pingsAfter = Process.GetProcessesByName("PING").Length;

        Assert.True(pingsBefore >= 1, "expected spawned ping processes before kill");
        Assert.True(pingsAfter < pingsBefore, "tree kill should have removed the spawned children");
    }
}
