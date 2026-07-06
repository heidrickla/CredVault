using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;

namespace CredVault.Native;

/// <summary>
/// Opts a window's non-client area (the OS title bar) into dark mode via
/// DWM, so the whole window reads dark rather than a light title bar on
/// top of a dark client area. No-op on OS versions that don't support it.
/// </summary>
public static class WindowTheming
{
    // DWMWA_USE_IMMERSIVE_DARK_MODE: 20 on Windows 10 20H1+ / Windows 11,
    // 19 on the earlier 1809-1909 builds. Try the modern one, then fall back.
    private const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;
    private const int DWMWA_USE_IMMERSIVE_DARK_MODE_LEGACY = 19;

    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);

    public static void ApplyDarkTitleBar(Window window)
    {
        var hwnd = new WindowInteropHelper(window).Handle;
        if (hwnd == IntPtr.Zero)
            return;

        int useDark = 1;
        if (DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, ref useDark, sizeof(int)) != 0)
            DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE_LEGACY, ref useDark, sizeof(int));
    }
}
