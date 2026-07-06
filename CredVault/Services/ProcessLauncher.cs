using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security;
using System.Threading;
using CredVault.Native;

namespace CredVault.Services;

/// <summary>
/// Thrown before any process starts when a selected credential's literal
/// value is found inside the command line. Carries only the credential
/// <see cref="CredentialName"/> - never the value - so it is safe to log
/// or display.
/// </summary>
public sealed class SecretInCommandLineException : Exception
{
    public string CredentialName { get; }

    public SecretInCommandLineException(string credentialName)
        : base($"The command line contains the stored value of '{credentialName}'.")
    {
        CredentialName = credentialName;
    }
}

/// <summary>
/// Starts a child process with selected credentials injected as
/// environment variables scoped to that process alone. Built on
/// System.Diagnostics.Process, which calls CreateProcess in
/// kernel32.dll under the hood - the environment block it builds
/// lives only in the child process's memory, never in a file this
/// app writes, and never in anything the caller (e.g. Claude Code)
/// reads back except stdout/stderr/exit code.
///
/// Two programmatic guardrails protect the injected values:
///
///  1. Output redaction - every stdout/stderr line is scrubbed of any
///     injected value before it reaches the caller's log, so a tested
///     script that echoes its own env var cannot leak the value into
///     CredVault's log. (Partial/split-across-lines matches can still
///     slip through - this reduces the risk, it is not a guarantee.)
///
///  2. Command-line secret rejection - if ANY stored credential's literal
///     value appears in the command line, the launch is refused before the
///     process starts. That both prevents the value reaching the child's
///     command line (visible in Task Manager / WMI to other processes) and
///     stops it being written to the persisted last-command settings file.
///     All stored credentials are checked (not just the selected ones), so a
///     value pasted for an unchecked credential is caught too.
/// </summary>
public static class ProcessLauncher
{
    private const string RedactionMarker = "«redacted»";

    public static Process Launch(string commandLine, IReadOnlyList<string> credentialNames, Action<string> onOutput)
    {
        var (fileName, arguments) = SplitCommand(commandLine);

        // Guardrail 2: refuse before doing anything else if any stored
        // credential's value was typed/pasted onto the command line. Scanning
        // ALL stored credentials (not only the selected ones) also covers a
        // value pasted for an unchecked credential. Backed by CredentialCache
        // (values held encrypted); nothing is logged and the exception carries
        // only the name.
        RejectSecretsOnCommandLine(commandLine);

        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = arguments,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        // Values injected this launch, used only to scrub them back out of
        // the child's output. These already live in startInfo.Environment
        // (and thus the child's memory) for the process lifetime, so holding
        // a parallel copy for redaction is not a larger exposure. The list is
        // cleared once both output streams have drained (see below).
        var redactions = new List<string>();

        foreach (var name in credentialNames)
        {
            if (!CredentialManager.TryRead(name, out var secret) || secret is null)
            {
                onOutput($"skip: no stored credential named '{name}'");
                continue;
            }

            var plain = ToPlainString(secret);
            secret.Dispose();

            startInfo.Environment[name] = plain;
            if (plain.Length > 0)
                redactions.Add(plain);
            onOutput($"injected {name} (value hidden)");
        }

        // Guardrail 1: scrub injected values out of every output line.
        string Scrub(string line)
        {
            foreach (var value in redactions)
                line = line.Replace(value, RedactionMarker, StringComparison.Ordinal);
            return line;
        }

        var process = new Process { StartInfo = startInfo, EnableRaisingEvents = true };

        var streamsOpen = 2;
        void OnData(DataReceivedEventArgs e)
        {
            if (e.Data is not null)
            {
                onOutput(Scrub(e.Data));
            }
            else if (Interlocked.Decrement(ref streamsOpen) == 0)
            {
                // Both streams have signalled end-of-output; drop the plaintext
                // copies now rather than waiting for GC. (Managed strings are
                // immutable and cannot be zeroed - clearing the list only
                // removes our references.)
                redactions.Clear();
            }
        }

        process.OutputDataReceived += (_, e) => OnData(e);
        process.ErrorDataReceived += (_, e) => OnData(e);

        process.Start();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        onOutput($"child process started, pid {process.Id}");

        return process;
    }

    private static void RejectSecretsOnCommandLine(string commandLine)
    {
        // Scans all stored credentials via the cache (values held encrypted as
        // SecureString, decrypted only momentarily here) so we avoid a
        // Credential Manager round-trip per credential on every launch.
        var hit = CredentialCache.FindValueIn(commandLine);
        if (hit is not null)
            throw new SecretInCommandLineException(hit);
    }

    private static (string fileName, string arguments) SplitCommand(string commandLine)
    {
        commandLine = commandLine.Trim();
        if (commandLine.Length == 0)
            return (string.Empty, string.Empty);

        // Honor a quoted executable so paths containing spaces
        // (e.g. "C:\Program Files\app.exe" arg) resolve correctly
        // rather than being truncated at the first space.
        if (commandLine[0] == '"')
        {
            var closingQuote = commandLine.IndexOf('"', 1);
            if (closingQuote > 0)
            {
                var quotedFile = commandLine[1..closingQuote];
                var rest = commandLine[(closingQuote + 1)..].TrimStart();
                return (quotedFile, rest);
            }
        }

        var spaceIndex = commandLine.IndexOf(' ');
        return spaceIndex < 0
            ? (commandLine, string.Empty)
            : (commandLine[..spaceIndex], commandLine[(spaceIndex + 1)..]);
    }

    private static string ToPlainString(SecureString secure)
    {
        var ptr = Marshal.SecureStringToGlobalAllocUnicode(secure);
        try
        {
            return Marshal.PtrToStringUni(ptr) ?? string.Empty;
        }
        finally
        {
            Marshal.ZeroFreeGlobalAllocUnicode(ptr);
        }
    }
}
