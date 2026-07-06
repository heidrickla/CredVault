using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Threading;
using CredVault.Native;

namespace CredVault.Services;

/// <summary>
/// Thrown before any process starts when a stored credential's literal
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
/// Thrown when the target executable carries an Authenticode signature whose
/// digest no longer matches the file - i.e. the binary was modified after it
/// was signed. This is the one unambiguous tamper signal, so the launch is
/// refused. The message contains only the path, never a secret.
/// </summary>
public sealed class TamperedExecutableException : Exception
{
    public string ExecutablePath { get; }

    public TamperedExecutableException(string executablePath)
        : base($"Executable failed its Authenticode integrity check (modified after signing): {executablePath}")
    {
        ExecutablePath = executablePath;
    }
}

/// <summary>
/// The resolved, pinned, verified target of a launch - created by
/// <see cref="ProcessLauncher.Prepare"/> BEFORE any secret is read.
///
/// While a plan is alive it holds a read handle (FileShare.Read) on the
/// executable: other processes may read/execute it, but nothing can write,
/// delete, or rename it - closing the check-then-launch (TOCTOU) window
/// between verification and CreateProcess. Dispose releases the pin; the
/// launcher releases it automatically once the image is loaded.
/// </summary>
public sealed class LaunchPlan : IDisposable
{
    public string ResolvedPath { get; }
    public string Arguments { get; }

    /// <summary>Uppercase hex SHA-256 of the executable image.</summary>
    public string Sha256 { get; }

    /// <summary>Human-readable signature verdict for the session log.</summary>
    public string SignatureNote { get; }

    private FileStream? _pin;

    internal LaunchPlan(string resolvedPath, string arguments, string sha256, string signatureNote, FileStream pin)
    {
        ResolvedPath = resolvedPath;
        Arguments = arguments;
        Sha256 = sha256;
        SignatureNote = signatureNote;
        _pin = pin;
    }

    internal void ReleasePin()
    {
        _pin?.Dispose();
        _pin = null;
    }

    public void Dispose() => ReleasePin();
}

/// <summary>
/// Starts a child process with selected credentials injected as
/// environment variables scoped to that process alone.
///
/// Launching is indirect and two-phase:
///
///   Prepare(commandLine)  - no secrets touched yet:
///     * guardrail: refuse if any stored credential's value is in the
///       command line (fingerprint scan, see CredentialCache);
///     * resolve the executable to an absolute path using an explicit
///       search order (System32, Windows, absolute PATH entries) that never
///       includes the current or application directory;
///     * pin the file with a read handle so it cannot be modified or
///       swapped until the launch completes (TOCTOU);
///     * hash the image (SHA-256) for the caller's change tripwire;
///     * verify Authenticode: a signed image whose digest no longer matches
///       is refused outright.
///
///   Launch(plan, ...)     - only now are secret values read and placed in
///     the child's environment block, and every stdout/stderr line is
///     scrubbed of injected values (longest-first) before reaching the log.
/// </summary>
public static class ProcessLauncher
{
    private const string RedactionMarker = "«redacted»";

    public static LaunchPlan Prepare(string commandLine)
    {
        // Guardrail: no stored credential value on the command line. Runs
        // before resolution so nothing is ever done with a tainted command.
        RejectSecretsOnCommandLine(commandLine);

        var (token, arguments) = SplitCommand(commandLine);
        if (token.Length == 0)
            throw new Win32Exception(2); // ERROR_FILE_NOT_FOUND

        var resolved = ResolveExecutable(token) ?? throw new Win32Exception(2);

        FileStream pin;
        try
        {
            // FileShare.Read: others (including CreateProcess mapping the
            // image) can read, but writes, deletes, and renames are blocked
            // for as long as the plan holds this handle.
            pin = new FileStream(resolved, FileMode.Open, FileAccess.Read, FileShare.Read);
        }
        catch (FileNotFoundException) { throw new Win32Exception(2); }
        catch (DirectoryNotFoundException) { throw new Win32Exception(3); }
        catch (UnauthorizedAccessException) { throw new Win32Exception(5); }

        try
        {
            var sha256 = Convert.ToHexString(SHA256.HashData(pin));

            var (status, hresult) = AuthenticodeVerifier.Verify(resolved);
            if (status == SignatureStatus.TamperedSignature)
                throw new TamperedExecutableException(resolved);

            var note = status switch
            {
                SignatureStatus.ValidSignature => "embedded Authenticode signature valid",
                SignatureStatus.NoEmbeddedSignature => "no embedded Authenticode signature",
                _ => $"signature present but not validated (0x{hresult:X8})",
            };

            return new LaunchPlan(resolved, arguments, sha256, note, pin);
        }
        catch
        {
            pin.Dispose();
            throw;
        }
    }

    /// <summary>Convenience one-shot: Prepare + Launch.</summary>
    public static Process Launch(string commandLine, IReadOnlyList<string> credentialNames, Action<string> onOutput)
    {
        using var plan = Prepare(commandLine);
        return Launch(plan, credentialNames, onOutput);
    }

    public static Process Launch(LaunchPlan plan, IReadOnlyList<string> credentialNames, Action<string> onOutput)
    {
        onOutput($"resolved executable: {plan.ResolvedPath}");
        onOutput($"image sha256: {plan.Sha256}");
        onOutput($"signature: {plan.SignatureNote}");

        var startInfo = new ProcessStartInfo
        {
            FileName = plan.ResolvedPath,
            Arguments = plan.Arguments,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        // Secret values are read only HERE - after the target executable has
        // been resolved, pinned, and verified by Prepare. The parallel copy
        // in `redactions` exists to scrub the child's output; it is cleared
        // once both output streams drain.
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

        // Redact longest-first: if one secret is a substring of another,
        // replacing the shorter one first would break the longer match and
        // leave its remainder visible in the output.
        redactions.Sort(static (a, b) => b.Length.CompareTo(a.Length));

        // Guardrail: scrub injected values out of every output line.
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

        // The loader has mapped the image and keeps it write-locked for the
        // process lifetime; the plan's pin is no longer needed.
        plan.ReleasePin();

        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        onOutput($"child process started, pid {process.Id}");

        return process;
    }

    /// <summary>
    /// Resolves a command token to an absolute executable path. An explicit
    /// path (rooted, or containing a separator) is honored as typed; a bare
    /// name searches System32, the Windows directory, then absolute PATH
    /// entries. The current directory and the application directory are
    /// deliberately never searched - a planted binary there must not be
    /// picked up by a bare command name.
    /// </summary>
    private static string? ResolveExecutable(string token)
    {
        if (token.Contains('\\') || token.Contains('/') || Path.IsPathRooted(token))
            return TryWithExtensions(Path.GetFullPath(token));

        foreach (var dir in SearchDirectories())
        {
            var hit = TryWithExtensions(Path.Combine(dir, token));
            if (hit is not null)
                return hit;
        }

        return null;
    }

    private static IEnumerable<string> SearchDirectories()
    {
        yield return Environment.SystemDirectory;
        yield return Environment.GetFolderPath(Environment.SpecialFolder.Windows);

        var path = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
        foreach (var raw in path.Split(';'))
        {
            var dir = raw.Trim();
            // Relative PATH entries resolve against the CWD - skip them for
            // the same reason the CWD itself is excluded.
            if (dir.Length > 0 && Path.IsPathRooted(dir))
                yield return dir;
        }
    }

    private static string? TryWithExtensions(string basePath)
    {
        foreach (var ext in new[] { "", ".exe", ".cmd", ".bat" })
        {
            var candidate = basePath + ext;
            if (File.Exists(candidate))
                return candidate;
        }
        return null;
    }

    private static void RejectSecretsOnCommandLine(string commandLine)
    {
        // Scans all stored credentials via the fingerprint cache (one-way
        // HMACs, no retained values) so we avoid a Credential Manager
        // round-trip per credential on every launch.
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
