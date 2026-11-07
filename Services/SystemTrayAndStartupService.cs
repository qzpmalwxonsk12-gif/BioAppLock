using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using Microsoft.Win32;

namespace BioAppLock.Services
{
    public class SystemTrayService : IDisposable
    {
        public const int WM_TRAYICON = 0x8000 + 101;
        private const int WM_LBUTTONUP = 0x0202;
        private const int WM_LBUTTONDBLCLK = 0x0203;
        private const int WM_RBUTTONUP = 0x0205;

        private const uint NIM_ADD = 0x00000000;
        private const uint NIM_MODIFY = 0x00000001;
        private const uint NIM_DELETE = 0x00000002;

        private const uint NIF_MESSAGE = 0x00000001;
        private const uint NIF_ICON = 0x00000002;
        private const uint NIF_TIP = 0x00000004;
        private const uint NIF_INFO = 0x00000010;

        private const uint NIIF_INFO = 0x00000001;
        private static readonly IntPtr IDI_SHIELD = new IntPtr(32518);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct NOTIFYICONDATAW
        {
            public uint cbSize;
            public IntPtr hWnd;
            public uint uID;
            public uint uFlags;
            public uint uCallbackMessage;
            public IntPtr hIcon;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string szTip;
            public uint dwState;
            public uint dwStateMask;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string szInfo;
            public uint uTimeoutOrVersion;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
            public string szInfoTitle;
            public uint dwInfoFlags;
            public Guid guidItem;
            public IntPtr hBalloonIcon;
        }

        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        private static extern bool Shell_NotifyIconW(uint dwMessage, ref NOTIFYICONDATAW lpData);

        [DllImport("user32.dll")]
        private static extern IntPtr LoadIcon(IntPtr hInstance, IntPtr lpIconName);

        private IntPtr _hwnd;
        private IntPtr _hIcon;
        private bool _isAdded;
        private readonly ContextMenu _trayMenu;

        public event Action? OpenDashboardRequested;
        public event Action? LockAllAppsRequested;
        public event Action? ExitCompletelyRequested;

        public SystemTrayService()
        {
            _trayMenu = BuildTrayContextMenu();
        }

        public void Initialize(IntPtr windowHandle)
        {
            if (_isAdded || windowHandle == IntPtr.Zero) return;
            _hwnd = windowHandle;
            _hIcon = LoadIcon(IntPtr.Zero, IDI_SHIELD);

            var data = CreateBaseData();
            data.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
            data.szTip = "BioShield App Guard — Biometric Protection Active";

            _isAdded = Shell_NotifyIconW(NIM_ADD, ref data);
        }

        public void ShowNotification(string title, string message)
        {
            if (!_isAdded || _hwnd == IntPtr.Zero) return;

            var data = CreateBaseData();
            data.uFlags = NIF_INFO | NIF_TIP;
            data.szTip = "BioShield App Guard — Biometric Protection Active";
            data.szInfoTitle = title;
            data.szInfo = message;
            data.dwInfoFlags = NIIF_INFO;
            data.uTimeoutOrVersion = 3000;

            Shell_NotifyIconW(NIM_MODIFY, ref data);
        }

        public void HandleWindowMessage(int msg, IntPtr lParam)
        {
            if (msg != WM_TRAYICON) return;

            int mouseMsg = (int)(lParam.ToInt64() & 0xFFFF);
            if (mouseMsg == WM_LBUTTONUP || mouseMsg == WM_LBUTTONDBLCLK)
            {
                OpenDashboardRequested?.Invoke();
            }
            else if (mouseMsg == WM_RBUTTONUP)
            {
                _trayMenu.IsOpen = true;
            }
        }

        private ContextMenu BuildTrayContextMenu()
        {
            var menu = new ContextMenu();

            var openItem = new MenuItem { Header = "🛡️ Open BioShield Dashboard", FontWeight = FontWeights.Bold };
            openItem.Click += (_, _) => OpenDashboardRequested?.Invoke();

            var lockAllItem = new MenuItem { Header = "🔒 Lock & Minimize All Protected Apps Now (Ctrl+Alt+L)" };
            lockAllItem.Click += (_, _) => LockAllAppsRequested?.Invoke();

            var exitItem = new MenuItem { Header = "⏻ Quit BioShield Completely (Requires Fingerprint / PIN)" };
            exitItem.Click += (_, _) => ExitCompletelyRequested?.Invoke();

            menu.Items.Add(openItem);
            menu.Items.Add(new Separator());
            menu.Items.Add(lockAllItem);
            menu.Items.Add(new Separator());
            menu.Items.Add(exitItem);

            return menu;
        }

        private NOTIFYICONDATAW CreateBaseData()
        {
            return new NOTIFYICONDATAW
            {
                cbSize = (uint)Marshal.SizeOf<NOTIFYICONDATAW>(),
                hWnd = _hwnd,
                uID = 1,
                uCallbackMessage = WM_TRAYICON,
                hIcon = _hIcon,
                szTip = string.Empty,
                szInfo = string.Empty,
                szInfoTitle = string.Empty
            };
        }

        public void Dispose()
        {
            if (_isAdded && _hwnd != IntPtr.Zero)
            {
                var data = CreateBaseData();
                Shell_NotifyIconW(NIM_DELETE, ref data);
                _isAdded = false;
            }
        }
    }

    public static class StartupRegistryService
    {
        private const string RunRegistryPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
        private const string ValueName = "BioShieldAppGuard";

        public static bool IsStartupEnabled()
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(RunRegistryPath, false);
                return key?.GetValue(ValueName) is string val && !string.IsNullOrWhiteSpace(val);
            }
            catch
            {
                return false;
            }
        }

        public static void SetStartupEnabled(bool enabled)
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(RunRegistryPath, true);
                if (key == null) return;

                if (enabled)
                {
                    string exePath = Environment.ProcessPath
                        ?? Process.GetCurrentProcess().MainModule?.FileName
                        ?? string.Empty;

                    if (!string.IsNullOrEmpty(exePath))
                    {
                        key.SetValue(ValueName, $"\"{exePath}\" --background");
                    }
                }
                else
                {
                    if (key.GetValue(ValueName) != null)
                    {
                        key.DeleteValue(ValueName, false);
                    }
                }
            }
            catch
            {
            }
        }
    }
}
