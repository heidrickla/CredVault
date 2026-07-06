# CredVault

A small native Windows tool for testing authentication flows with Claude
Code without ever putting real credentials into the chat context window.

## How it works

1. **Storage** — secrets are saved via the Windows Credential Manager
   (`advapi32.dll`: `CredWrite`/`CredRead`/`CredDelete`/`CredEnumerate`),
   which encrypts them at rest with DPAPI, scoped to your Windows user
   account. All entries are namespaced under `CredVault:<name>` so the
   app only ever sees credentials it created.
2. **Reference, not value** — you name a credential (e.g.
   `TEST_DB_PASSWORD`) and write test code against
   `Environment.GetEnvironmentVariable("TEST_DB_PASSWORD")` /
   `os.environ["TEST_DB_PASSWORD"]`. Claude Code only ever needs the name.
3. **Injection at launch** — check the credentials you want, enter a
   command, and hit Launch. `ProcessLauncher` starts that one child
   process with the values set in *its* environment block only, via
   `System.Diagnostics.Process` (which itself calls `CreateProcess` in
   `kernel32.dll`). Nothing is written to a file, and the values never
   appear in this app's own log — only the names do.

## Managing credentials

- **Add** — name + secret; stored under `CredVault:<name>`.
- **Edit** — replaces the stored value in place via `CredWrite` under the
  same name (no delete-then-recreate). The dialog never reads the current
  secret back out; you type a fresh value, and the name is shown read-only
  because it is the storage key.
- **Remove** — deletes from Credential Manager, then re-reads the whole
  list from the store so the UI always mirrors what is actually persisted.

## Launching

- **Launch** is disabled while the command box is empty and while a child
  process is already running.
- If the process can't start (bad path, access denied, not an executable),
  an inline error explains what went wrong instead of only logging a raw
  exception string.
- Executables whose path contains spaces can be quoted, e.g.
  `"C:\Program Files\app\tool.exe" --flag`.
- **Cancel** kills the entire process tree, so a shell or wrapper that
  spawned its own children (a script launching sub-processes) is fully
  terminated, not just the top-level process.
- The last-used command line is remembered across restarts (see caveats).

## Build

Requires the .NET SDK with the Windows desktop workload (`net10.0-windows`).

```powershell
cd CredVault
dotnet build
dotnet run --project CredVault
```

Or open `CredVault.sln` in Visual Studio and run.

## Built-in guardrails

Programmatic protections back up the "reference, not value" design so a
mistake doesn't quietly leak a secret:

1. **Output redaction.** Every stdout/stderr line from the child is scrubbed
   of any injected value before it reaches the log (longest value first, so
   one secret being a substring of another can't leave a partial remnant).
   A test script that echoes its own env var (`echo %TEST_DB_PASSWORD%`)
   shows up as `the password is «redacted»`. See the limit below — this
   catches whole, contiguous occurrences, not values the script transforms
   first.
2. **Command-line secret rejection.** If *any stored* credential's literal
   value is present in the command line (selected or not), the launch is
   refused before the process starts, with an inline error naming the
   credential. This keeps the value out of the child's command line (which
   other processes can read via Task Manager / WMI) and out of the persisted
   command file. The scan is backed by a fingerprint cache: values are
   reduced to one-way HMAC-SHA256 fingerprints under a random per-process
   key — no values are retained in memory, and store timestamps are checked
   each launch so edits made outside the app (cmdkey, control panel) are
   picked up.
3. **Env-var name validation.** Credential names must be valid
   environment-variable names (no `=`, whitespace, or control characters),
   and names of loader-/security-sensitive variables (`PATH`, `COMSPEC`,
   CLR profiler hooks, …) are refused outright.
4. **Executable search hardening.** Bare command names resolve through an
   explicit search order (System32 → Windows → absolute `PATH` entries) that
   never includes the current or application directory, so a planted exe
   can't be picked up by a bare command name and handed the injected
   secrets. (`NoDefaultCurrentDirectoryInExePath` is also set as defense in
   depth.) Native P/Invoke libraries resolve from System32 only.
5. **Pinned, verified launch (indirect launch).** Launching is two-phase.
   Before any secret is read, the resolved executable is *pinned* with a
   read handle so it cannot be modified, deleted, or renamed between
   verification and `CreateProcess` (closing the TOCTOU window); its
   SHA-256 is logged and compared against the last launch of the same path,
   prompting for confirmation if the binary changed; and its Authenticode
   signature is checked — a signed image whose digest no longer matches
   (modified after signing) is refused outright. Unsigned executables are
   allowed (most dev tools are unsigned) but labeled in the log. Secrets
   are injected only after all of this passes. Note: this verifies the
   executable image, not script arguments — `pwsh -File test.ps1` verifies
   `pwsh.exe`; the script is your own test code.

## Security notes / caveats

- **`SecureString` is marked obsolete in modern .NET** but still works
  and is used here for defense-in-depth in memory. It does not fully
  prevent memory-scraping attacks — treat this as raising the bar, not
  as a guarantee.
- **The child process's environment is plaintext in its own memory** —
  that's inherent to how every OS process environment works. Output
  redaction (guardrail 1) scrubs verbatim occurrences of injected values
  from stdout/stderr, but it **cannot** catch a value the tested app
  *transforms* before printing (base64/hex-encoded, uppercased, split
  across lines, embedded in a URL, etc.), nor a value written to the app's
  own log file or sent over the network. Still write test scripts that
  don't handle secrets carelessly — the guardrail is a safety net, not a
  license to log them.
- `ProcessStartInfo.Environment` holds a plain managed `string` for each
  injected value, and the redaction set holds a copy for the process
  lifetime (dropped once both output streams drain). Managed strings are
  immutable and can't be zeroed, so they live until GC. For a hardened
  build, replace this with pinned unmanaged buffers and explicit zeroing.
- Credentials persist at `CRED_PERSIST_LOCAL_MACHINE` scope (survive
  reboot, tied to your user profile). Remove ones you no longer need via
  the "Remove" button.
- This is a local dev/test tool, not a secrets manager for production
  systems or a team-shared vault — there's no access control beyond
  your Windows login.
- **The settings file holds no secrets.** `%AppData%\CredVault\settings.json`
  stores only the last-used command *text* so it survives restarts, and
  only a command that has passed the secret-in-command-line check and been
  launched is ever written. Credential values live solely in Credential
  Manager. Guardrail 2 blocks a pasted-in value, but the safe habit is
  still to reference credentials by name and let injection supply them.

## Project layout

```
CredVault/
  CredVault.csproj
  App.xaml / App.xaml.cs
  MainWindow.xaml / MainWindow.xaml.cs        UI: list, launcher, log
  AddCredentialWindow.xaml / .xaml.cs         Add-credential dialog
  Models/CredentialEntry.cs                   UI-bound credential row
  Native/CredentialManager.cs                 advapi32.dll P/Invoke wrapper
  Services/ProcessLauncher.cs                 env-var injection + process launch
  Services/AppSettings.cs                     non-secret UI state (last command)
```
