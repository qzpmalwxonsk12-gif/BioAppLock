using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using BioAppLock.Models;

namespace BioAppLock.Services
{
    public static class Win32Api
    {
        public delegate void WinEventDelegate(
            IntPtr hWinEventHook,
            uint eventType,
            IntPtr hwnd,
            int idObject,
            int idChild,
            uint dwEventThread,
            uint dwmsEventTime);

        public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        public const uint EVENT_SYSTEM_FOREGROUND = 0x0003;
        public const uint EVENT_SYSTEM_MINIMIZESTART = 0x0016;
        public const uint EVENT_SYSTEM_MINIMIZEEND = 0x0017;
        public const uint WINEVENT_OUTOFCONTEXT = 0x0000;
        public const uint WINEVENT_SKIPOWNPROCESS = 0x0002;

        public const int SW_HIDE = 0;
        public const int SW_SHOWNORMAL = 1;
        public const int SW_SHOWMINIMIZED = 2;
        public const int SW_MAXIMIZE = 3;
        public const int SW_SHOWNOACTIVATE = 4;
        public const int SW_SHOW = 5;
        public const int SW_MINIMIZE = 6;
        public const int SW_SHOWMINNOACTIVE = 7;
        public const int SW_RESTORE = 9;
        public const int SW_FORCEMINIMIZE = 11;

        public const int GWL_EXSTYLE = -20;
        public const int WS_EX_TOOLWINDOW = 0x00000080;
        public const int WS_EX_APPWINDOW = 0x00040000;

        public static readonly IntPtr HWND_TOPMOST = new IntPtr(-1);
        public static readonly IntPtr HWND_NOTOPMOST = new IntPtr(-2);
        public static readonly IntPtr HWND_TOP = new IntPtr(0);

        public const uint SWP_NOSIZE = 0x0001;
        public const uint SWP_NOMOVE = 0x0002;
        public const uint SWP_NOACTIVATE = 0x0010;
        public const uint SWP_SHOWWINDOW = 0x0040;

        public const uint MOD_ALT = 0x0001;
        public const uint MOD_CONTROL = 0x0002;
        public const uint MOD_SHIFT = 0x0004;
        public const uint VK_L = 0x4C;

        [DllImport("user32.dll")]
        public static extern IntPtr SetWinEventHook(
            uint eventMin,
            uint eventMax,
            IntPtr hmodWinEventProc,
            WinEventDelegate lpfnWinEventProc,
            uint idProcess,
            uint idThread,
            uint dwFlags);

        [DllImport("user32.dll")]
        public static extern bool UnhookWinEvent(IntPtr hWinEventHook);

        [DllImport("user32.dll")]
        public static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll")]
        public static extern IntPtr GetShellWindow();

        [DllImport("user32.dll")]
        public static extern bool IsWindow(IntPtr hWnd);

        [DllImport("user32.dll")]
        public static extern bool IsWindowVisible(IntPtr hWnd);

        [DllImport("user32.dll")]
        public static extern bool IsIconic(IntPtr hWnd);

        [DllImport("user32.dll")]
        public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        [DllImport("user32.dll")]
        public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);

        [DllImport("user32.dll")]
        public static extern bool SetForegroundWindow(IntPtr hWnd);

        [DllImport("user32.dll")]
        public static extern IntPtr SetActiveWindow(IntPtr hWnd);

        [DllImport("user32.dll")]
        public static extern IntPtr SetFocus(IntPtr hWnd);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        public static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

        [DllImport("user32.dll")]
        public static extern bool BringWindowToTop(IntPtr hWnd);

        [DllImport("user32.dll")]
        public static extern bool SetWindowPos(
            IntPtr hWnd,
            IntPtr hWndInsertAfter,
            int X,
            int Y,
            int cx,
            int cy,
            uint uFlags);

        [DllImport("user32.dll")]
        public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        [DllImport("user32.dll")]
        public static extern uint GetWindowThreadProcessId(IntPtr hWnd, IntPtr ProcessId);

        [DllImport("kernel32.dll")]
        public static extern uint GetCurrentThreadId();

        [DllImport("user32.dll")]
        public static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, bool fAttach);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        public static extern int GetWindowTextLength(IntPtr hWnd);

        [DllImport("user32.dll")]
        public static extern int GetWindowLong(IntPtr hWnd, int nIndex);

        [DllImport("user32.dll")]
        public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

        [DllImport("user32.dll")]
        public static extern bool EnumChildWindows(IntPtr hWndParent, EnumWindowsProc lpEnumFunc, IntPtr lParam);

        [DllImport("user32.dll")]
        public static extern bool RegisterHotKey(IntPtr hWnd, int id, uint fsModifiers, uint vk);

        [DllImport("user32.dll")]
        public static extern bool UnregisterHotKey(IntPtr hWnd, int id);

        [DllImport("user32.dll")]
        private static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);

        private const byte VK_MENU = 0x12;
        private const uint KEYEVENTF_EXTENDEDKEY = 0x0001;
        private const uint KEYEVENTF_KEYUP = 0x0002;

        public static string GetWindowTitle(IntPtr hWnd)
        {
            if (hWnd == IntPtr.Zero) return string.Empty;
            int length = GetWindowTextLength(hWnd);
            if (length <= 0) return string.Empty;
            var sb = new StringBuilder(length + 1);
            GetWindowText(hWnd, sb, sb.Capacity);
            return sb.ToString();
        }

        public static (uint ProcessId, string ProcessName) GetWindowProcessInfo(IntPtr hWnd)
        {
            if (hWnd == IntPtr.Zero) return (0, string.Empty);
            GetWindowThreadProcessId(hWnd, out uint pid);
            if (pid == 0) return (0, string.Empty);

            string procName = GetProcessNameSafe(pid);

            // Handle UWP ApplicationFrameHost wrapper windows
            if (string.Equals(procName, "ApplicationFrameHost", StringComparison.OrdinalIgnoreCase))
            {
                uint realPid = pid;
                EnumChildWindows(hWnd, (childHwnd, _) =>
                {
                    GetWindowThreadProcessId(childHwnd, out uint childPid);
                    if (childPid != 0 && childPid != pid)
                    {
                        realPid = childPid;
                        return false;
                    }
                    return true;
                }, IntPtr.Zero);

                if (realPid != pid)
                {
                    string childName = GetProcessNameSafe(realPid);
                    if (!string.IsNullOrEmpty(childName))
                    {
                        return (realPid, childName);
                    }
                }
            }

            return (pid, procName);
        }

        private static string GetProcessNameSafe(uint pid)
        {
            try
            {
                using var proc = Process.GetProcessById((int)pid);
                return proc.ProcessName ?? string.Empty;
            }
            catch
            {
                return string.Empty;
            }
        }

        /// <summary>
        /// Immediately forces a window to minimize so its contents are hidden without killing or suspending the background process.
        /// </summary>
        public static void ForceMinimizeWindow(IntPtr hWnd)
        {
            if (hWnd == IntPtr.Zero || !IsWindow(hWnd)) return;
            try
            {
                ShowWindowAsync(hWnd, SW_SHOWMINNOACTIVE);
                ShowWindow(hWnd, SW_FORCEMINIMIZE);
            }
            catch
            {
                // Ignore if elevated process window refuses direct command
            }
        }

        /// <summary>
        /// Finds the active Windows Security (Windows Hello Fingerprint / PIN) dialog window (CredentialUIBroker.exe).
        /// </summary>
        public static IntPtr FindCredentialUiWindow()
        {
            IntPtr foundHwnd = IntPtr.Zero;

            EnumWindows((hWnd, _) =>
            {
                if (!IsWindowVisible(hWnd)) return true;

                var classSb = new StringBuilder(128);
                GetClassName(hWnd, classSb, classSb.Capacity);
                string className = classSb.ToString();

                if (string.Equals(className, "Credential Dialog Xaml Host", StringComparison.OrdinalIgnoreCase))
                {
                    foundHwnd = hWnd;
                    return false;
                }

                var (pid, procName) = GetWindowProcessInfo(hWnd);
                if (pid != 0 && string.Equals(procName, "CredentialUIBroker", StringComparison.OrdinalIgnoreCase))
                {
                    foundHwnd = hWnd;
                    return false;
                }

                return true;
            }, IntPtr.Zero);

            return foundHwnd;
        }

        /// <summary>
        /// Ensures the Windows Security (CredentialUIBroker.exe) window is the active foreground window
        /// so the Windows Biometric Service (WbioSrvc) routes fingerprint sensor input to it immediately.
        /// </summary>
        public static void ForceFocusCredentialWindow(IntPtr credHwnd)
        {
            if (credHwnd == IntPtr.Zero || !IsWindow(credHwnd)) return;
            try
            {
                IntPtr fgWindow = GetForegroundWindow();
                if (fgWindow == credHwnd) return;

                uint fgThread = GetWindowThreadProcessId(fgWindow, IntPtr.Zero);
                uint currentThread = GetCurrentThreadId();
                uint credThread = GetWindowThreadProcessId(credHwnd, IntPtr.Zero);

                bool attachedFg = false;
                bool attachedCred = false;

                try
                {
                    if (fgThread != 0 && fgThread != currentThread)
                        attachedFg = AttachThreadInput(currentThread, fgThread, true);
                    if (credThread != 0 && credThread != currentThread)
                        attachedCred = AttachThreadInput(currentThread, credThread, true);

                    SetWindowPos(credHwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
                    BringWindowToTop(credHwnd);
                    SetForegroundWindow(credHwnd);
                    SetActiveWindow(credHwnd);
                    SetFocus(credHwnd);
                }
                finally
                {
                    if (attachedFg) AttachThreadInput(currentThread, fgThread, false);
                    if (attachedCred) AttachThreadInput(currentThread, credThread, false);
                }
            }
            catch
            {
            }
        }

        /// <summary>
        /// Restores a minimized window and reliably brings it to the foreground after biometric verification succeeds.
        /// </summary>
        public static void ForceRestoreAndFocusWindow(IntPtr hWnd)
        {
            if (hWnd == IntPtr.Zero || !IsWindow(hWnd)) return;
            try
            {
                IntPtr fgWindow = GetForegroundWindow();
                uint fgThread = GetWindowThreadProcessId(fgWindow, IntPtr.Zero);
                uint currentThread = GetCurrentThreadId();
                uint targetThread = GetWindowThreadProcessId(hWnd, IntPtr.Zero);

                bool attachedFg = false;
                bool attachedTarget = false;

                try
                {
                    if (fgThread != 0 && fgThread != currentThread)
                        attachedFg = AttachThreadInput(currentThread, fgThread, true);
                    if (targetThread != 0 && targetThread != currentThread)
                        attachedTarget = AttachThreadInput(currentThread, targetThread, true);

                    if (IsIconic(hWnd))
                    {
                        ShowWindow(hWnd, SW_RESTORE);
                    }
                    else
                    {
                        ShowWindow(hWnd, SW_SHOW);
                    }

                    // Brief synthetic ALT tap helps Windows allow foreground transition from dialog
                    keybd_event(VK_MENU, 0, KEYEVENTF_EXTENDEDKEY, UIntPtr.Zero);
                    keybd_event(VK_MENU, 0, KEYEVENTF_EXTENDEDKEY | KEYEVENTF_KEYUP, UIntPtr.Zero);

                    BringWindowToTop(hWnd);
                    SetWindowPos(hWnd, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
                    SetForegroundWindow(hWnd);
                }
                finally
                {
                    if (attachedFg) AttachThreadInput(currentThread, fgThread, false);
                    if (attachedTarget) AttachThreadInput(currentThread, targetThread, false);
                }
            }
            catch
            {
            }
        }

        public static List<RunningWindowItem> EnumRunningDesktopWindows(uint ignorePid = 0)
        {
            var result = new List<RunningWindowItem>();
            IntPtr shellWindow = GetShellWindow();
            int currentPid = Environment.ProcessId;

            EnumWindows((hWnd, _) =>
            {
                if (hWnd == shellWindow) return true;
                if (!IsWindowVisible(hWnd)) return true;

                int exStyle = GetWindowLong(hWnd, GWL_EXSTYLE);
                bool isToolWindow = (exStyle & WS_EX_TOOLWINDOW) != 0;
                bool isAppWindow = (exStyle & WS_EX_APPWINDOW) != 0;
                if (isToolWindow && !isAppWindow) return true;

                string title = GetWindowTitle(hWnd);
                if (string.IsNullOrWhiteSpace(title)) return true;
                if (title == "Program Manager" || title == "Windows Input Experience" || title == "Settings")
                {
                    // Allow Settings if it's real SystemSettings
                }
                if (title == "Program Manager" || title == "Windows Input Experience" || title == "Default IME")
                    return true;

                var (pid, procName) = GetWindowProcessInfo(hWnd);
                if (pid == 0 || pid == currentPid || (ignorePid != 0 && pid == ignorePid)) return true;
                if (string.IsNullOrWhiteSpace(procName)) return true;

                // Skip internal shell/overlay hosts
                if (string.Equals(procName, "TextInputHost", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(procName, "SearchHost", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(procName, "ShellExperienceHost", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                result.Add(new RunningWindowItem
                {
                    Hwnd = hWnd,
                    ProcessId = pid,
                    ProcessName = procName,
                    WindowTitle = title,
                    IsMinimized = IsIconic(hWnd)
                });

                return true;
            }, IntPtr.Zero);

            return result;
        }
    }
}
