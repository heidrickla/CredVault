using System.ComponentModel;
using System.Diagnostics;
using System.IO;
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
    public void Guardrail_reflects_an_in_app_value_edit_not_a_stale_cache()
    {
        using var cred = NewCredentialName();
        CredentialManager.Save(cred.Name, Secure("old-value-abc"));

        // Prime the cache: a launch that scans (and caches) the current value.
        RunAndCollect("cmd /c exit");

        // Overwrite the value in-app; this must invalidate the cache.
        CredentialManager.Save(cred.Name, Secure("new-value-xyz"));

        // The guardrail must catch the NEW value (proving the cache refreshed)...
        var ex = Assert.Throws<SecretInCommandLineException>(() =>
            ProcessLauncher.Launch("cmd /c echo new-value-xyz", Array.Empty<string>(), _ => { }));
        Assert.Equal(cred.Name, ex.CredentialName);

        // ...and the old value must no longer trip it (it is gone from the store).
        var log = RunAndCollect("cmd /c echo old-value-abc");
        Assert.Contains(log, l => l.Contains("child process started"));
    }

    [Fact]
    public void Guardrail_detects_a_value_changed_outside_the_app()
    {
        using var cred = NewCredentialName();
        CredentialManager.Save(cred.Name, Secure("first-value-000"));

        // Prime the fingerprint cache with the current value.
        RunAndCollect("cmd /c exit 0");

        // Overwrite the value OUTSIDE the app: cmdkey does not raise our
        // in-app change event, so only the LastWritten reconcile can see it.
        using (var external = Process.Start(new ProcessStartInfo("cmdkey.exe",
                   $"/generic:CredVault:{cred.Name} /user:test /pass:external-value-777")
               { UseShellExecute = false, CreateNoWindow = true }))
        {
            Assert.True(external!.WaitForExit(10_000));
            Assert.Equal(0, external.ExitCode);
        }

        var ex = Assert.Throws<SecretInCommandLineException>(() =>
            ProcessLauncher.Launch("cmd /c echo external-value-777", Array.Empty<string>(), _ => { }));
        Assert.Equal(cred.Name, ex.CredentialName);
    }

    [Fact]
    public void Redaction_covers_overlapping_secrets_without_partial_leak()
    {
        using var shorter = NewCredentialName();
        using var longer = NewCredentialName();
        CredentialManager.Save(shorter.Name, Secure("OVERLAP-secret-AAA"));
        CredentialManager.Save(longer.Name, Secure("OVERLAP-secret-AAA-TAIL-BBB"));

        // Child echoes the LONGER value; if the shorter secret were replaced
        // first, the tail "-TAIL-BBB" would remain visible in the output.
        var log = RunAndCollect($"cmd /c echo %{longer.Name}%", shorter.Name, longer.Name);

        Assert.DoesNotContain(log, l => l.Contains("TAIL-BBB"));
        Assert.DoesNotContain(log, l => l.Contains("OVERLAP-secret-AAA"));
        Assert.Contains(log, l => l.Contains("«redacted»"));
    }

    [Fact]
    public void Missing_executable_throws_file_not_found_Win32Exception()
    {
        var ex = Assert.Throws<Win32Exception>(() =>
            ProcessLauncher.Launch(@"C:\definitely\not\here\nope.exe", Array.Empty<string>(), _ => { }));

        Assert.Equal(2, ex.NativeErrorCode); // ERROR_FILE_NOT_FOUND
    }

    [Fact]
    public void Launch_logs_resolved_path_hash_and_signature()
    {
        var log = RunAndCollect("cmd /c exit 0");

        Assert.Contains(log, l => l.StartsWith("resolved executable:")
                                  && l.Contains(@"\cmd.exe", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(log, l => l.StartsWith("image sha256: ") && l.Length >= 64);
        Assert.Contains(log, l => l.StartsWith("signature:"));
    }

    [Fact]
    public void Prepare_pins_the_executable_against_modification_until_released()
    {
        var temp = Path.Combine(Path.GetTempPath(), $"credvault-pin-{Guid.NewGuid():N}.exe");
        File.Copy(Path.Combine(Environment.SystemDirectory, "cmd.exe"), temp);
        try
        {
            var plan = ProcessLauncher.Prepare($"\"{temp}\" /c exit 0");
            Assert.Equal(temp, plan.ResolvedPath, ignoreCase: true);

            // While the plan is alive the binary cannot be modified or
            // deleted - the TOCTOU window between verify and launch is shut.
            Assert.Throws<IOException>(() => File.OpenWrite(temp).Dispose());
            Assert.ThrowsAny<IOException>(() => File.Delete(temp));

            plan.Dispose();

            // Released: writable again.
            File.OpenWrite(temp).Dispose();
        }
        finally
        {
            File.Delete(temp);
        }
    }

    [Fact]
    public void Prepare_refuses_a_tampered_signed_executable()
    {
        // Needs an embedded-Authenticode-signed binary; dotnet.exe (always
        // present on this dev box - it runs this test suite) qualifies.
        var source = (Environment.GetEnvironmentVariable("PATH") ?? string.Empty).Split(';')
            .Select(p => p.Trim())
            .Where(p => p.Length > 0 && Path.IsPathRooted(p))
            .Select(p => Path.Combine(p, "dotnet.exe"))
            .FirstOrDefault(File.Exists);
        Assert.False(source is null, "dotnet.exe not found on PATH - cannot exercise the tamper check");

        var temp = Path.Combine(Path.GetTempPath(), $"credvault-tamper-{Guid.NewGuid():N}.exe");
        File.Copy(source!, temp);
        try
        {
            // Flip one byte in the middle of the image: the embedded
            // signature's digest no longer matches the file.
            using (var fs = new FileStream(temp, FileMode.Open, FileAccess.ReadWrite))
            {
                fs.Position = fs.Length / 2;
                var original = fs.ReadByte();
                fs.Position = fs.Length / 2;
                fs.WriteByte((byte)(original ^ 0xFF));
            }

            var ex = Assert.Throws<TamperedExecutableException>(() =>
                ProcessLauncher.Prepare($"\"{temp}\""));
            Assert.Equal(temp, ex.ExecutablePath, ignoreCase: true);
        }
        finally
        {
            File.Delete(temp);
        }
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
