using System.Windows;

namespace CredVault;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        // Security hardening: CreateProcess normally includes the current
        // working directory in its executable search path, so a malicious
        // exe dropped into CredVault's CWD (e.g. a fake "pwsh.exe") could be
        // launched when the user types a bare command name - and it would
        // receive the injected secrets. Defining this documented variable
        // removes the CWD from the search path for every process this app
        // starts (children inherit it, which also protects their launches).
        Environment.SetEnvironmentVariable("NoDefaultCurrentDirectoryInExePath", "1");

        base.OnStartup(e);
    }
}
