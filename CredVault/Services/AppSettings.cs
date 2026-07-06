using System.IO;
using System.Text.Json;

namespace CredVault.Services;

/// <summary>
/// Tiny local settings store for non-secret UI state that should
/// survive app restarts - currently just the last-used command line.
///
/// IMPORTANT: only non-secret values belong here. This file is written
/// in plaintext to %AppData%\CredVault\settings.json. Credential values
/// live exclusively in Windows Credential Manager (DPAPI) and must never
/// be persisted through this class.
/// </summary>
public sealed class AppSettings
{
    public string LastCommand { get; set; } = string.Empty;

    /// <summary>
    /// SHA-256 (hex) of each executable previously launched, keyed by
    /// lower-cased absolute path. Used as a change tripwire: if the binary
    /// at a known path hashes differently on the next launch, the user is
    /// asked to confirm before any secret is injected. Hashes identify
    /// public binaries - they are not secrets.
    /// </summary>
    public Dictionary<string, string> KnownExecutableHashes { get; set; } = new();

    private static string SettingsPath
    {
        get
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "CredVault");
            return Path.Combine(dir, "settings.json");
        }
    }

    public static AppSettings Load()
    {
        try
        {
            var path = SettingsPath;
            if (File.Exists(path))
            {
                var json = File.ReadAllText(path);
                var loaded = JsonSerializer.Deserialize<AppSettings>(json);
                if (loaded is not null)
                    return loaded;
            }
        }
        catch
        {
            // Corrupt/unreadable settings are non-fatal - fall back to defaults.
        }

        return new AppSettings();
    }

    public void Save()
    {
        try
        {
            var path = SettingsPath;
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            var json = JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(path, json);
        }
        catch
        {
            // Best-effort persistence; a failure to save UI state must not
            // crash the app or interrupt a launch.
        }
    }
}
