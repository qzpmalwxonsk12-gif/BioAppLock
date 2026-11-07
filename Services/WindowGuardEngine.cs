using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Threading;
using BioAppLock.Models;

namespace BioAppLock.Services
{
    public class WindowGuardEngine : IDisposable
    {
        private readonly AppConfig _config;
        private readonly Dispatcher _dispatcher;
        private readonly DispatcherTimer _watchdogTimer;
        private readonly Win32Api.WinEventDelegate _winEventDelegate;

        private IntPtr _hookForeground = IntPtr.Zero;
        private IntPtr _hookMinimizeStart = IntPtr.Zero;
        private IntPtr _hookMinimizeEnd = IntPtr.Zero;

        private LockShieldWindow? _activeShieldWindow;
        private IntPtr _activeTargetHwnd = IntPtr.Zero;
        private DateTime _lastCancelTime = DateTime.MinValue;
        private IntPtr _lastCanceledHwnd = IntPtr.Zero;

        public ObservableCollection<SecurityAuditEntry> AuditLogs { get; } = new();

        public event Action? StateChanged;
        public event Action<ProtectedAppRule, IntPtr>? InterceptionTriggered;

        public bool IsShieldCurrentlyOpen => _activeShieldWindow != null;
        public LockShieldWindow? ActiveShieldWindow => _activeShieldWindow;

        public WindowGuardEngine(AppConfig config)
        {
            _config = config;
            _dispatcher = Application.Current.Dispatcher;

            // Keep delegate alive in field to prevent GC collection
            _winEventDelegate = OnWinEventCallback;

            _watchdogTimer = new DispatcherTimer(DispatcherPriority.Send, _dispatcher)
            {
                Interval = TimeSpan.FromMilliseconds(30)
            };
            _watchdogTimer.Tick += OnWatchdogTick;
        }

        public void Start()
        {
            if (_hookForeground == IntPtr.Zero)
            {
                uint flags = Win32Api.WINEVENT_OUTOFCONTEXT | Win32Api.WINEVENT_SKIPOWNPROCESS;
                _hookForeground = Win32Api.SetWinEventHook(
                    Win32Api.EVENT_SYSTEM_FOREGROUND,
                    Win32Api.EVENT_SYSTEM_FOREGROUND,
                    IntPtr.Zero,
                    _winEventDelegate,
                    0, 0, flags);

                _hookMinimizeStart = Win32Api.SetWinEventHook(
                    Win32Api.EVENT_SYSTEM_MINIMIZESTART,
                    Win32Api.EVENT_SYSTEM_MINIMIZEEND,
                    IntPtr.Zero,
                    _winEventDelegate,
                    0, 0, flags);
            }

            // Initialize initial unlock state based on whether protected apps are currently minimized
            SyncInitialWindowStates();

            _watchdogTimer.Start();
            AddAudit("ARMED", "BioShield Engine", "Real-time Win32 hook & Windows Hello biometric guard started.");
        }

        public void Stop()
        {
            _watchdogTimer.Stop();
            if (_hookForeground != IntPtr.Zero)
            {
                Win32Api.UnhookWinEvent(_hookForeground);
                _hookForeground = IntPtr.Zero;
            }
            if (_hookMinimizeStart != IntPtr.Zero)
            {
                Win32Api.UnhookWinEvent(_hookMinimizeStart);
                _hookMinimizeStart = IntPtr.Zero;
            }
            if (_hookMinimizeEnd != IntPtr.Zero)
            {
                Win32Api.UnhookWinEvent(_hookMinimizeEnd);
                _hookMinimizeEnd = IntPtr.Zero;
            }
        }

        private void SyncInitialWindowStates()
        {
            var runningWindows = Win32Api.EnumRunningDesktopWindows((uint)Environment.ProcessId);
            foreach (var rule in _config.Rules)
            {
                var matchingWins = runningWindows.Where(w => DoesWindowMatchRule(w.ProcessName, w.WindowTitle, rule)).ToList();
                if (matchingWins.Count == 0 || matchingWins.All(w => w.IsMinimized))
                {
                    // If app is closed or minimized right now, ensure it is ARMED (Locked)
                    rule.IsCurrentlyUnlocked = false;
                }
                else if (rule.IsCurrentlyUnlocked)
                {
                    rule.UnlockedAt = DateTime.Now;
                }
            }
        }

        private void OnWinEventCallback(
            IntPtr hWinEventHook,
            uint eventType,
            IntPtr hwnd,
            int idObject,
            int idChild,
            uint dwEventThread,
            uint dwmsEventTime)
        {
            if (hwnd == IntPtr.Zero || idObject != 0) return;
            if (!_config.IsMasterProtectionEnabled) return;
            if (_activeShieldWindow != null) return;

            var (pid, procName) = Win32Api.GetWindowProcessInfo(hwnd);
            if (pid == 0 || pid == Environment.ProcessId) return;

            string title = Win32Api.GetWindowTitle(hwnd);
            var rule = FindMatchingEnabledRule(procName, title);
            if (rule == null) return;

            if (eventType == Win32Api.EVENT_SYSTEM_MINIMIZESTART)
            {
                // Protected window was just minimized -> immediately re-lock if LockImmediatelyOnMinimize is enabled
                if (_config.LockImmediatelyOnMinimize && rule.IsCurrentlyUnlocked)
                {
                    if (rule.UnlockedAt == null || (DateTime.Now - rule.UnlockedAt.Value).TotalMilliseconds > 600)
                    {
                        rule.IsCurrentlyUnlocked = false;
                        rule.LastUnfocusedAt = null;
                        AddAudit("RELOCKED", rule.DisplayName, $"Window minimized ({procName}.exe) — Protection re-armed.");
                        StateChanged?.Invoke();
                    }
                }
                return;
            }

            if (eventType == Win32Api.EVENT_SYSTEM_MINIMIZEEND || eventType == Win32Api.EVENT_SYSTEM_FOREGROUND)
            {
                if (!rule.IsCurrentlyUnlocked)
                {
                    // Immediately force minimize BEFORE UI renders content
                    Win32Api.ForceMinimizeWindow(hwnd);
                    _dispatcher.BeginInvoke(() => TriggerSecurityShield(rule, hwnd, procName, title), DispatcherPriority.Send);
                }
            }
        }

        private void OnWatchdogTick(object? sender, EventArgs e)
        {
            if (!_config.IsMasterProtectionEnabled) return;

            // If Shield is currently open, ensure the intercepted target window stays minimized
            if (_activeShieldWindow != null)
            {
                if (_activeTargetHwnd != IntPtr.Zero && !Win32Api.IsIconic(_activeTargetHwnd))
                {
                    Win32Api.ForceMinimizeWindow(_activeTargetHwnd);
                }
                return;
            }

            IntPtr fgHwnd = Win32Api.GetForegroundWindow();
            uint fgPid = 0;
            string fgProcName = string.Empty;
            string fgTitle = string.Empty;

            if (fgHwnd != IntPtr.Zero)
            {
                (fgPid, fgProcName) = Win32Api.GetWindowProcessInfo(fgHwnd);
                fgTitle = Win32Api.GetWindowTitle(fgHwnd);
            }

            // 1. Check if foreground window is a locked protected app
            if (fgHwnd != IntPtr.Zero && fgPid != 0 && fgPid != Environment.ProcessId && !Win32Api.IsIconic(fgHwnd))
            {
                var fgRule = FindMatchingEnabledRule(fgProcName, fgTitle);
                if (fgRule != null)
                {
                    if (!fgRule.IsCurrentlyUnlocked)
                    {
                        // Check brief cancel cooldown for the same window if it's already minimizing
                        if (_lastCanceledHwnd == fgHwnd && (DateTime.Now - _lastCancelTime).TotalMilliseconds < 350)
                        {
                            Win32Api.ForceMinimizeWindow(fgHwnd);
                            return;
                        }

                        Win32Api.ForceMinimizeWindow(fgHwnd);
                        TriggerSecurityShield(fgRule, fgHwnd, fgProcName, fgTitle);
                        return;
                    }
                    else
                    {
                        // Currently focused on this unlocked app -> reset unfocused timer
                        fgRule.LastUnfocusedAt = null;
                    }
                }
            }

            // 2. Check unlocked rules for Auto-Relock on Minimize or Switch-Away
            var runningWindows = Win32Api.EnumRunningDesktopWindows((uint)Environment.ProcessId);

            foreach (var rule in _config.Rules.Where(r => r.IsEnabled && r.IsCurrentlyUnlocked))
            {
                // Give 1.5s grace period right after unlocking so the window restore animation completes cleanly
                if (rule.UnlockedAt.HasValue && (DateTime.Now - rule.UnlockedAt.Value).TotalMilliseconds < 1500)
                {
                    continue;
                }

                var ruleWindows = runningWindows.Where(w => DoesWindowMatchRule(w.ProcessName, w.WindowTitle, rule)).ToList();

                // A1. If all windows of this protected app have been closed, ALWAYS re-arm the lock!
                if (ruleWindows.Count == 0)
                {
                    rule.IsCurrentlyUnlocked = false;
                    rule.LastUnfocusedAt = null;
                    AddAudit("RELOCKED", rule.DisplayName, "Application closed — Fingerprint/PIN lock re-armed for next launch.");
                    StateChanged?.Invoke();
                    continue;
                }

                // A2. If all windows of this app are minimized -> re-lock immediately!
                if (_config.LockImmediatelyOnMinimize && ruleWindows.All(w => w.IsMinimized))
                {
                    rule.IsCurrentlyUnlocked = false;
                    rule.LastUnfocusedAt = null;
                    AddAudit("RELOCKED", rule.DisplayName, "Application minimized — Fingerprint/PIN protection re-armed.");
                    StateChanged?.Invoke();
                    continue;
                }

                // B. Check Switch-Away (Focus Loss) auto-relock
                if (_config.LockOnSwitchAway && fgPid != 0 && fgPid != Environment.ProcessId)
                {
                    bool isFgThisRule = DoesWindowMatchRule(fgProcName, fgTitle, rule);
                    bool isTransientSystemUi = IsTransientSystemProcess(fgProcName);

                    if (!isFgThisRule && !isTransientSystemUi)
                    {
                        if (rule.LastUnfocusedAt == null)
                        {
                            rule.LastUnfocusedAt = DateTime.Now;
                        }
                        else if ((DateTime.Now - rule.LastUnfocusedAt.Value).TotalSeconds >= _config.SwitchAwayGraceSeconds)
                        {
                            rule.IsCurrentlyUnlocked = false;
                            rule.LastUnfocusedAt = null;

                            if (_config.AutoMinimizeOnLock)
                            {
                                foreach (var win in ruleWindows.Where(w => !w.IsMinimized))
                                {
                                    Win32Api.ForceMinimizeWindow(win.Hwnd);
                                }
                            }

                            AddAudit("RELOCKED", rule.DisplayName, $"Switched away for {_config.SwitchAwayGraceSeconds}s — App re-locked.");
                            StateChanged?.Invoke();
                        }
                    }
                    else if (isFgThisRule)
                    {
                        rule.LastUnfocusedAt = null;
                    }
                }
            }
        }

        private void TriggerSecurityShield(ProtectedAppRule rule, IntPtr targetHwnd, string procName, string title)
        {
            if (_activeShieldWindow != null) return;

            // Ensure target window is minimized so its content is never visible
            Win32Api.ForceMinimizeWindow(targetHwnd);

            AddAudit("INTERCEPTED", rule.DisplayName, $"Intercepted attempt to open/switch to '{title}' ({procName}.exe).");
            InterceptionTriggered?.Invoke(rule, targetHwnd);

            var shield = new LockShieldWindow(rule, targetHwnd, title, _config);
            _activeShieldWindow = shield;
            _activeTargetHwnd = targetHwnd;

            shield.Closed += async (_, _) =>
            {
                bool authenticated = shield.IsAuthenticated;
                string method = shield.AuthMethod;
                _activeShieldWindow = null;
                _activeTargetHwnd = IntPtr.Zero;

                if (authenticated)
                {
                    rule.IsCurrentlyUnlocked = true;
                    rule.UnlockedAt = DateTime.Now;
                    rule.LastUnfocusedAt = null;

                    AddAudit("VERIFIED", rule.DisplayName, $"Identity verified via {method}. Restoring application.");
                    StateChanged?.Invoke();

                    await System.Threading.Tasks.Task.Delay(60);
                    Win32Api.ForceRestoreAndFocusWindow(targetHwnd);
                }
                else
                {
                    rule.BlockedAttempts++;
                    _lastCancelTime = DateTime.Now;
                    _lastCanceledHwnd = targetHwnd;

                    Win32Api.ForceMinimizeWindow(targetHwnd);
                    AddAudit("BLOCKED", rule.DisplayName, $"Access blocked — Biometric/PIN verification canceled ({rule.BlockedAttempts} total blocked).");
                    StateChanged?.Invoke();
                }
            };

            shield.Show();
            shield.Activate();
        }

        public void LockRuleAndMinimizeWindows(ProtectedAppRule rule)
        {
            rule.IsCurrentlyUnlocked = false;
            rule.LastUnfocusedAt = null;

            var runningWindows = Win32Api.EnumRunningDesktopWindows((uint)Environment.ProcessId);
            foreach (var win in runningWindows.Where(w => DoesWindowMatchRule(w.ProcessName, w.WindowTitle, rule)))
            {
                Win32Api.ForceMinimizeWindow(win.Hwnd);
            }

            AddAudit("RELOCKED", rule.DisplayName, "Manually locked & minimized — Fingerprint/PIN required to view.");
            StateChanged?.Invoke();
        }

        public void LockAllProtectedAppsNow()
        {
            var runningWindows = Win32Api.EnumRunningDesktopWindows((uint)Environment.ProcessId);
            foreach (var rule in _config.Rules.Where(r => r.IsEnabled))
            {
                rule.IsCurrentlyUnlocked = false;
                rule.LastUnfocusedAt = null;

                foreach (var win in runningWindows.Where(w => DoesWindowMatchRule(w.ProcessName, w.WindowTitle, rule)))
                {
                    Win32Api.ForceMinimizeWindow(win.Hwnd);
                }
            }

            AddAudit("RELOCKED", "All Protected Apps", "Panic Lock triggered — All protected apps minimized & armed.");
            StateChanged?.Invoke();
        }

        public ProtectedAppRule? FindMatchingEnabledRule(string processName, string windowTitle)
        {
            foreach (var rule in _config.Rules)
            {
                if (!rule.IsEnabled) continue;
                if (DoesWindowMatchRule(processName, windowTitle, rule))
                    return rule;
            }
            return null;
        }

        public static bool DoesWindowMatchRule(string processName, string windowTitle, ProtectedAppRule rule)
        {
            string cleanRuleProc = NormalizeProcessName(rule.ProcessName);
            string cleanActualProc = NormalizeProcessName(processName);

            if (!string.IsNullOrWhiteSpace(cleanRuleProc))
            {
                if (string.Equals(cleanActualProc, cleanRuleProc, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            if (string.IsNullOrWhiteSpace(cleanRuleProc) && !string.IsNullOrWhiteSpace(rule.TitleKeyword))
            {
                if (!string.IsNullOrWhiteSpace(windowTitle) &&
                    windowTitle.Contains(rule.TitleKeyword.Trim(), StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        public static string NormalizeProcessName(string? name)
        {
            if (string.IsNullOrWhiteSpace(name)) return string.Empty;
            string trimmed = name.Trim();
            if (trimmed.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                trimmed = Path.GetFileNameWithoutExtension(trimmed);
            }
            return trimmed;
        }

        private static bool IsTransientSystemProcess(string procName)
        {
            if (string.IsNullOrWhiteSpace(procName)) return true;
            return string.Equals(procName, "CredentialUIBroker", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(procName, "ShellExperienceHost", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(procName, "SearchHost", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(procName, "StartMenuExperienceHost", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(procName, "TextInputHost", StringComparison.OrdinalIgnoreCase);
        }

        public void AddAudit(string eventType, string appName, string details)
        {
            _dispatcher.InvokeAsync(() =>
            {
                AuditLogs.Insert(0, new SecurityAuditEntry
                {
                    Timestamp = DateTime.Now,
                    EventType = eventType,
                    AppName = appName,
                    Details = details
                });

                while (AuditLogs.Count > 100)
                {
                    AuditLogs.RemoveAt(AuditLogs.Count - 1);
                }
            });
        }

        public void Dispose()
        {
            Stop();
        }
    }
}
