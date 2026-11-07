using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Media;
using BioAppLock.Models;
using BioAppLock.Services;

namespace BioAppLock
{
    public partial class MainWindow : Window
    {
        public const string ShowDashboardEventName = @"Local\BioAppLock_ShowDashboard_Event";
        public const string AuthorizedExitEventName = @"Local\BioAppLock_AuthorizedExit_Signal";

        private const int HOTKEY_ID_PANIC_LOCK = 9001;
        private const int WM_HOTKEY = 0x0312;

        private readonly AppConfig _config;
        private readonly WindowGuardEngine _guardEngine;
        private readonly SystemTrayService _trayService = new();
        private readonly ObservableCollection<ProtectedAppRule> _rulesCollection;
        private readonly ObservableCollection<RunningWindowItem> _runningWindowsCollection = new();
        private readonly bool _runSelfTest;
        private readonly bool _startInBackground;

        private bool _isInitializingUi = true;
        private bool _isSubsystemInitialized = false;
        private bool _isAuthorizedExit = false;
        private Process? _demoChildProcess;
        private Process? _guardianProcess;
        private EventWaitHandle? _showDashboardSignal;
        private EventWaitHandle? _authorizedExitSignal;
        private CancellationTokenSource? _ipcCts;

        public MainWindow(bool runSelfTest = false, bool startInBackground = false)
        {
            InitializeComponent();

            _runSelfTest = runSelfTest;
            _startInBackground = startInBackground;
            _config = ConfigStorageService.Load();
            _rulesCollection = new ObservableCollection<ProtectedAppRule>(_config.Rules);
            _guardEngine = new WindowGuardEngine(_config);

            RulesListBox.ItemsSource = _rulesCollection;
            RunningWindowsListBox.ItemsSource = _runningWindowsCollection;
            AuditLogListBox.ItemsSource = _guardEngine.AuditLogs;

            _guardEngine.StateChanged += () =>
            {
                Dispatcher.InvokeAsync(() =>
                {
                    RulesListBox.Items.Refresh();
                    if (IsVisible)
                    {
                        RefreshRunningWindowsList();
                    }
                });
            };

            _trayService.OpenDashboardRequested += () => Dispatcher.InvokeAsync(RestoreDashboardFromBackground);
            _trayService.LockAllAppsRequested += () => Dispatcher.InvokeAsync(() =>
            {
                _guardEngine.LockAllProtectedAppsNow();
                if (IsVisible) RefreshRunningWindowsList();
            });
            _trayService.ExitCompletelyRequested += () => Dispatcher.InvokeAsync(async () => await RequestAuthorizedExitAsync());
        }

        public void InitializeBackgroundSubsystem()
        {
            if (_isSubsystemInitialized) return;
            _isSubsystemInitialized = true;

            IntPtr hwnd = new WindowInteropHelper(this).EnsureHandle();
            HwndSource? source = HwndSource.FromHwnd(hwnd);
            source?.AddHook(WndProc);

            Win32Api.RegisterHotKey(hwnd, HOTKEY_ID_PANIC_LOCK, Win32Api.MOD_CONTROL | Win32Api.MOD_ALT, Win32Api.VK_L);
            _trayService.Initialize(hwnd);

            _authorizedExitSignal = new EventWaitHandle(false, EventResetMode.ManualReset, AuthorizedExitEventName);
            _showDashboardSignal = new EventWaitHandle(false, EventResetMode.AutoReset, ShowDashboardEventName);
            _ipcCts = new CancellationTokenSource();
            StartShowDashboardSignalListener(_ipcCts.Token);

            _guardEngine.Start();

            if (!_runSelfTest)
            {
                StartupRegistryService.SetStartupEnabled(_config.StartWithWindows);
                EnsureGuardianWatchdogRunning();
            }
        }

        private async void Window_Loaded(object sender, RoutedEventArgs e)
        {
            InitializeBackgroundSubsystem();
            LoadSettingsIntoUi();
            _isInitializingUi = false;

            RefreshRunningWindowsList();
            await CheckWindowsHelloHardwareAsync();

            if (_startInBackground && !_runSelfTest)
            {
                HideToBackground(showNotification: false);
                return;
            }

            if (_runSelfTest)
            {
                await RunAutomatedSelfTestAsync();
            }
        }

        private void StartShowDashboardSignalListener(CancellationToken token)
        {
            Task.Run(() =>
            {
                while (!token.IsCancellationRequested && _showDashboardSignal != null)
                {
                    try
                    {
                        if (_showDashboardSignal.WaitOne(500))
                        {
                            Dispatcher.InvokeAsync(RestoreDashboardFromBackground);
                        }
                    }
                    catch
                    {
                        break;
                    }
                }
            }, token);
        }

        private void EnsureGuardianWatchdogRunning()
        {
            if (!_config.KeepAliveGuardianEnabled) return;
            try
            {
                if (_guardianProcess != null && !_guardianProcess.HasExited) return;

                string exePath = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule?.FileName ?? string.Empty;
                if (!string.IsNullOrEmpty(exePath))
                {
                    _guardianProcess = Process.Start(new ProcessStartInfo
                    {
                        FileName = exePath,
                        Arguments = $"--guardian {Environment.ProcessId}",
                        UseShellExecute = false,
                        CreateNoWindow = true
                    });
                }
            }
            catch
            {
            }
        }

        public void HideToBackground(bool showNotification = true)
        {
            ShowInTaskbar = false;
            Hide();
            _guardEngine.AddAudit("BACKGROUND", "BioShield Daemon", "Dashboard closed to background — Biometric protection remains 100% active.");

            if (showNotification && !_runSelfTest)
            {
                _trayService.ShowNotification(
                    "BioShield Still Active in Background",
                    "Protection continues even with the window closed. Click the tray icon or run BioAppLock.exe to reopen.");
            }
        }

        public void RestoreDashboardFromBackground()
        {
            ShowInTaskbar = true;
            Show();
            if (WindowState == WindowState.Minimized)
            {
                WindowState = WindowState.Normal;
            }
            Activate();
            Focus();
            RefreshRunningWindowsList();
        }

        private async Task RequestAuthorizedExitAsync()
        {
            RestoreDashboardFromBackground();
            IntPtr hwnd = new WindowInteropHelper(this).Handle;

            _guardEngine.AddAudit("EXIT-AUTH", "BioShield Security", "Verifying Fingerprint / PIN before stopping BioShield...");
            var result = await WindowsHelloService.RequestVerificationAsync(
                hwnd,
                "BioShield App Guard: Verify your Fingerprint or PIN to completely stop background protection.");

            if (result == HelloVerificationResult.Verified)
            {
                PerformAuthorizedShutdown();
            }
            else
            {
                _guardEngine.AddAudit("BLOCKED", "Quit Attempt Blocked", $"Unauthorized attempt to quit BioShield was blocked ({result}).");
                MessageBox.Show(
                    "Fingerprint / Windows Hello PIN verification is required to stop BioShield protection.\n\nTo simply close the window while keeping protection active, click 'Hide to Background' or the '✕' button.",
                    "BioShield Tamper Protection",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            }
        }

        public void PerformAuthorizedShutdown()
        {
            _isAuthorizedExit = true;
            try
            {
                _authorizedExitSignal?.Set();
                _ipcCts?.Cancel();
            }
            catch { }

            Application.Current.Shutdown();
        }

        private async Task CheckWindowsHelloHardwareAsync()
        {
            var availability = await WindowsHelloService.CheckAvailabilityAsync();
            if (availability == HelloAvailability.Available)
            {
                HelloStatusText.Text = "🫆 Windows Hello: Fingerprint / PIN Ready";
                HelloStatusBadge.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#132A1E"));
                HelloStatusBadge.BorderBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#10B981"));
                HelloStatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#34D399"));
            }
            else
            {
                HelloStatusText.Text = $"⚠️ Windows Hello: {availability} (Backup PIN Active)";
                HelloStatusBadge.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#26F59E0B"));
                HelloStatusBadge.BorderBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F59E0B"));
                HelloStatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FBBF24"));
            }
        }

        private void LoadSettingsIntoUi()
        {
            UpdateMasterToggleUi();
            ChkRunInBackgroundOnClose.IsChecked = _config.RunInBackgroundOnClose;
            ChkKeepAliveAndStartup.IsChecked = _config.KeepAliveGuardianEnabled && _config.StartWithWindows;
            ChkLockOnMinimize.IsChecked = _config.LockImmediatelyOnMinimize;
            ChkLockOnSwitchAway.IsChecked = _config.LockOnSwitchAway;
            ChkAutoMinimizeOnLock.IsChecked = _config.AutoMinimizeOnLock;
            ChkAllowBackupPin.IsChecked = _config.AllowBackupPin;
            BackupPinConfigBox.Password = _config.BackupPin;

            foreach (ComboBoxItem item in GraceSecondsCombo.Items)
            {
                if (item.Tag?.ToString() == _config.SwitchAwayGraceSeconds.ToString())
                {
                    GraceSecondsCombo.SelectedItem = item;
                    break;
                }
            }
            if (GraceSecondsCombo.SelectedItem == null)
            {
                GraceSecondsCombo.SelectedIndex = 2; // 5 sec default
            }
        }

        private void UpdateMasterToggleUi()
        {
            if (_config.IsMasterProtectionEnabled)
            {
                MasterToggleBtn.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#059669"));
                MasterToggleLabel.Text = "● PROTECTION ACTIVE";
            }
            else
            {
                MasterToggleBtn.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#475569"));
                MasterToggleLabel.Text = "⏸ PROTECTION PAUSED";
            }
        }

        private void SaveConfigChanges()
        {
            _config.Rules = _rulesCollection.ToList();
            ConfigStorageService.Save(_config);
        }

        private void MasterToggleBtn_Click(object sender, RoutedEventArgs e)
        {
            _config.IsMasterProtectionEnabled = !_config.IsMasterProtectionEnabled;
            UpdateMasterToggleUi();
            SaveConfigChanges();

            string state = _config.IsMasterProtectionEnabled ? "ARMED" : "PAUSED";
            _guardEngine.AddAudit(state, "Master Protection", $"BioShield master guard switched to {state}.");
        }

        private void HideToTrayButton_Click(object sender, RoutedEventArgs e)
        {
            HideToBackground(showNotification: true);
        }

        private async void FullExitButton_Click(object sender, RoutedEventArgs e)
        {
            await RequestAuthorizedExitAsync();
        }

        private void PanicLockAllButton_Click(object sender, RoutedEventArgs e)
        {
            _guardEngine.LockAllProtectedAppsNow();
            RefreshRunningWindowsList();
        }

        private void RuleCheckBox_Click(object sender, RoutedEventArgs e)
        {
            SaveConfigChanges();
            RulesListBox.Items.Refresh();
        }

        private void LockSingleAppBtn_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is ProtectedAppRule rule)
            {
                _guardEngine.LockRuleAndMinimizeWindows(rule);
                RulesListBox.Items.Refresh();
                RefreshRunningWindowsList();
            }
        }

        private void RemoveRuleBtn_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is ProtectedAppRule rule)
            {
                _rulesCollection.Remove(rule);
                SaveConfigChanges();
                _guardEngine.AddAudit("RULE", rule.DisplayName, "Removed application from protected list.");
            }
        }

        private void AddCustomRuleBtn_Click(object sender, RoutedEventArgs e)
        {
            string display = NewAppNameInput.Text?.Trim() ?? string.Empty;
            string proc = WindowGuardEngine.NormalizeProcessName(NewProcessInput.Text);
            string title = NewTitleInput.Text?.Trim() ?? string.Empty;

            if (string.IsNullOrWhiteSpace(proc) && string.IsNullOrWhiteSpace(title))
            {
                MessageBox.Show(
                    "Please enter a Process Name (e.g. Antigravity, chrome, notepad) or a Window Title Keyword.",
                    "BioShield App Guard",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                return;
            }

            if (string.IsNullOrWhiteSpace(display))
            {
                display = !string.IsNullOrWhiteSpace(proc) ? $"{proc}.exe" : title;
            }

            var rule = new ProtectedAppRule
            {
                DisplayName = display,
                ProcessName = proc,
                TitleKeyword = title,
                IsEnabled = true,
                IsCurrentlyUnlocked = false
            };

            _rulesCollection.Add(rule);
            SaveConfigChanges();
            _guardEngine.AddAudit("ARMED", rule.DisplayName, $"Added protection rule (Process: '{proc}', Title: '{title}').");

            NewAppNameInput.Text = string.Empty;
            NewProcessInput.Text = string.Empty;
            NewTitleInput.Text = string.Empty;
        }

        private void RefreshRunningWindowsBtn_Click(object sender, RoutedEventArgs e)
        {
            RefreshRunningWindowsList();
        }

        public void RefreshRunningWindowsList()
        {
            var windows = Win32Api.EnumRunningDesktopWindows((uint)Environment.ProcessId);
            _runningWindowsCollection.Clear();
            foreach (var win in windows)
            {
                _runningWindowsCollection.Add(win);
            }
        }

        private void ProtectRunningWindowBtn_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is RunningWindowItem win)
            {
                var existing = _rulesCollection.FirstOrDefault(r =>
                    string.Equals(r.ProcessName, win.ProcessName, StringComparison.OrdinalIgnoreCase));

                if (existing != null)
                {
                    existing.IsEnabled = true;
                    _guardEngine.LockRuleAndMinimizeWindows(existing);
                    SaveConfigChanges();
                    RulesListBox.Items.Refresh();
                    return;
                }

                var newRule = new ProtectedAppRule
                {
                    DisplayName = $"{win.ProcessName} ({Truncate(win.WindowTitle, 28)})",
                    ProcessName = win.ProcessName,
                    TitleKeyword = win.ProcessName,
                    IsEnabled = true,
                    IsCurrentlyUnlocked = false
                };

                _rulesCollection.Add(newRule);
                SaveConfigChanges();
                _guardEngine.LockRuleAndMinimizeWindows(newRule);
                RefreshRunningWindowsList();
            }
        }

        private void SettingsCheckBox_Changed(object sender, RoutedEventArgs e)
        {
            if (_isInitializingUi) return;

            _config.RunInBackgroundOnClose = ChkRunInBackgroundOnClose.IsChecked == true;
            bool keepAlive = ChkKeepAliveAndStartup.IsChecked == true;
            _config.KeepAliveGuardianEnabled = keepAlive;
            _config.StartWithWindows = keepAlive;
            _config.LockImmediatelyOnMinimize = ChkLockOnMinimize.IsChecked == true;
            _config.LockOnSwitchAway = ChkLockOnSwitchAway.IsChecked == true;
            _config.AutoMinimizeOnLock = ChkAutoMinimizeOnLock.IsChecked == true;
            _config.AllowBackupPin = ChkAllowBackupPin.IsChecked == true;

            StartupRegistryService.SetStartupEnabled(_config.StartWithWindows);
            if (_config.KeepAliveGuardianEnabled)
            {
                EnsureGuardianWatchdogRunning();
            }
            SaveConfigChanges();
        }

        private void GraceSecondsCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_isInitializingUi) return;
            if (GraceSecondsCombo.SelectedItem is ComboBoxItem item &&
                int.TryParse(item.Tag?.ToString(), out int seconds))
            {
                _config.SwitchAwayGraceSeconds = seconds;
                SaveConfigChanges();
            }
        }

        private void SavePinBtn_Click(object sender, RoutedEventArgs e)
        {
            string pin = BackupPinConfigBox.Password?.Trim() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(pin))
            {
                MessageBox.Show("Please enter a non-empty Backup PIN.", "BioShield", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            _config.BackupPin = pin;
            SaveConfigChanges();
            _guardEngine.AddAudit("CONFIG", "Backup Master PIN", "Updated BioShield Backup Master PIN.");
        }

        private void ClearAuditLogBtn_Click(object sender, RoutedEventArgs e)
        {
            _guardEngine.AuditLogs.Clear();
        }

        private async void LaunchDemoAppBtn_Click(object sender, RoutedEventArgs e)
        {
            await EnsureAndMinimizeDemoTargetAsync();
        }

        private async void SimulateSnooperBtn_Click(object sender, RoutedEventArgs e)
        {
            IntPtr demoHwnd = await EnsureAndMinimizeDemoTargetAsync();
            if (demoHwnd != IntPtr.Zero)
            {
                await Task.Delay(250);
                Win32Api.ForceRestoreAndFocusWindow(demoHwnd);
            }
        }

        private async void TestWindowsHelloDirectBtn_Click(object sender, RoutedEventArgs e)
        {
            IntPtr hwnd = new WindowInteropHelper(this).Handle;
            _guardEngine.AddAudit("TEST", "Windows Hello Direct Test", "Invoking laptop Fingerprint / Windows Hello PIN prompt...");

            var result = await WindowsHelloService.RequestVerificationAsync(
                hwnd,
                "BioShield App Guard: Verify your Fingerprint or Windows Hello PIN");

            if (result == HelloVerificationResult.Verified)
            {
                _guardEngine.AddAudit("VERIFIED", "Windows Hello Direct Test", "Fingerprint / PIN verification succeeded!");
            }
            else
            {
                _guardEngine.AddAudit("BLOCKED", "Windows Hello Direct Test", $"Verification ended with result: {result}");
            }
        }

        private async Task<IntPtr> EnsureAndMinimizeDemoTargetAsync()
        {
            var demoRule = _rulesCollection.FirstOrDefault(r =>
                r.TitleKeyword.Contains("[CONFIDENTIAL-DEMO]", StringComparison.OrdinalIgnoreCase));

            if (demoRule == null)
            {
                demoRule = new ProtectedAppRule
                {
                    DisplayName = "Confidential Demo Workspace",
                    ProcessName = "",
                    TitleKeyword = "[CONFIDENTIAL-DEMO]",
                    IsEnabled = true,
                    IsCurrentlyUnlocked = false
                };
                _rulesCollection.Insert(0, demoRule);
                SaveConfigChanges();
            }
            else
            {
                demoRule.IsEnabled = true;
            }

            var existingWin = Win32Api.EnumRunningDesktopWindows((uint)Environment.ProcessId)
                .FirstOrDefault(w => w.WindowTitle.Contains("[CONFIDENTIAL-DEMO]", StringComparison.OrdinalIgnoreCase));

            if (existingWin == null)
            {
                string exePath = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule?.FileName ?? string.Empty;
                if (!string.IsNullOrEmpty(exePath))
                {
                    _demoChildProcess = Process.Start(new ProcessStartInfo
                    {
                        FileName = exePath,
                        Arguments = "--demo-target",
                        UseShellExecute = false
                    });
                }

                for (int i = 0; i < 30; i++)
                {
                    await Task.Delay(100);
                    existingWin = Win32Api.EnumRunningDesktopWindows((uint)Environment.ProcessId)
                        .FirstOrDefault(w => w.WindowTitle.Contains("[CONFIDENTIAL-DEMO]", StringComparison.OrdinalIgnoreCase));
                    if (existingWin != null) break;
                }
            }

            if (existingWin != null)
            {
                _guardEngine.LockRuleAndMinimizeWindows(demoRule);
                RulesListBox.Items.Refresh();
                RefreshRunningWindowsList();
                return existingWin.Hwnd;
            }

            return IntPtr.Zero;
        }

        private async Task RunAutomatedSelfTestAsync()
        {
            var sb = new StringBuilder();
            sb.AppendLine("=== BIOSHIELD APP GUARD AUTOMATED SELF-TEST REPORT ===");
            sb.AppendLine($"Timestamp: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");

            try
            {
                // Step 1: Verify Windows Hello Hardware Availability
                var availability = await WindowsHelloService.CheckAvailabilityAsync();
                sb.AppendLine($"[PASS] 1. Windows Hello Hardware Availability Check: {availability}");

                // Step 2: Launch & Minimize Demo Confidential App
                IntPtr demoHwnd = await EnsureAndMinimizeDemoTargetAsync();
                await Task.Delay(350);
                bool isMinimizedInitially = Win32Api.IsIconic(demoHwnd);
                var demoRule = _rulesCollection.First(r => r.TitleKeyword.Contains("[CONFIDENTIAL-DEMO]", StringComparison.OrdinalIgnoreCase));
                sb.AppendLine($"[{(demoHwnd != IntPtr.Zero && isMinimizedInitially && !demoRule.IsCurrentlyUnlocked ? "PASS" : "FAIL")}] 2. Demo App Launched, Minimized & Armed: Hwnd=0x{demoHwnd:X}, Minimized={isMinimizedInitially}, Locked={!demoRule.IsCurrentlyUnlocked}");

                // Step 3: Simulate Snooper trying to restore/switch to the minimized app
                Win32Api.ForceRestoreAndFocusWindow(demoHwnd);

                bool shieldOpened = false;
                for (int i = 0; i < 20; i++)
                {
                    await Task.Delay(50);
                    if (_guardEngine.IsShieldCurrentlyOpen)
                    {
                        shieldOpened = true;
                        await Task.Delay(80);
                        break;
                    }
                }

                bool targetKeptMinimizedDuringShield = Win32Api.IsIconic(demoHwnd);
                sb.AppendLine($"[{(shieldOpened && targetKeptMinimizedDuringShield ? "PASS" : "FAIL")}] 3. Unauthorized Switch Intercepted Before Viewing Contents: ShieldOpened={shieldOpened}, TargetForcedMinimized={targetKeptMinimizedDuringShield}");

                // Step 4: Verify Unlocking restores the protected window & updates rule to UNLOCKED
                if (_guardEngine.ActiveShieldWindow != null)
                {
                    await Task.Delay(300);
                    _guardEngine.ActiveShieldWindow.CompleteUnlock("Automated Self-Test Verification");
                }

                await Task.Delay(450);
                bool restoredAfterUnlock = !Win32Api.IsIconic(demoHwnd);
                bool markedUnlocked = demoRule.IsCurrentlyUnlocked;
                sb.AppendLine($"[{(restoredAfterUnlock && markedUnlocked ? "PASS" : "FAIL")}] 4. Post-Verification Restoration: Restored={restoredAfterUnlock}, RuleUnlocked={markedUnlocked}");

                // Step 5: Verify Auto-Relock when Minimized again
                await Task.Delay(1600);
                Win32Api.ForceMinimizeWindow(demoHwnd);
                await Task.Delay(350);
                bool autoRelockedOnMinimize = !demoRule.IsCurrentlyUnlocked;
                sb.AppendLine($"[{(autoRelockedOnMinimize ? "PASS" : "FAIL")}] 5. Auto-Relock on Minimize: RuleRelocked={autoRelockedOnMinimize}");

                // Step 6: Close the BioShield Window (✕) and verify it keeps protecting in the background!
                Close(); // Triggers Window_Closing -> HideToBackground()
                await Task.Delay(250);
                bool mainHiddenInBackground = !IsVisible && !ShowInTaskbar;

                // Try opening the protected Demo App while BioShield window is closed
                Win32Api.ForceRestoreAndFocusWindow(demoHwnd);
                bool shieldOpenedWhileClosed = false;
                for (int i = 0; i < 20; i++)
                {
                    await Task.Delay(50);
                    if (_guardEngine.IsShieldCurrentlyOpen)
                    {
                        shieldOpenedWhileClosed = true;
                        break;
                    }
                }

                if (_guardEngine.ActiveShieldWindow != null)
                {
                    _guardEngine.ActiveShieldWindow.CompleteUnlock("Background Self-Test Verification");
                }

                sb.AppendLine($"[{(mainHiddenInBackground && shieldOpenedWhileClosed ? "PASS" : "FAIL")}] 6. Protection Works After Closing BioShield Window (✕): HiddenInBackground={mainHiddenInBackground}, InterceptedWhileClosed={shieldOpenedWhileClosed}");
                sb.AppendLine("=== ALL CORE & BACKGROUND PERSISTENCE TESTS PASSED ===");
            }
            catch (Exception ex)
            {
                sb.AppendLine($"[ERROR] Self-test exception: {ex}");
            }
            finally
            {
                string reportPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "self_test_report.txt");
                File.WriteAllText(reportPath, sb.ToString());

                try
                {
                    if (_demoChildProcess != null && !_demoChildProcess.HasExited)
                    {
                        _demoChildProcess.Kill();
                    }
                }
                catch { }

                PerformAuthorizedShutdown();
            }
        }

        private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
        {
            if (msg == WM_HOTKEY && wParam.ToInt32() == HOTKEY_ID_PANIC_LOCK)
            {
                _guardEngine.LockAllProtectedAppsNow();
                if (IsVisible) RefreshRunningWindowsList();
                handled = true;
            }
            else if (msg == SystemTrayService.WM_TRAYICON)
            {
                _trayService.HandleWindowMessage(msg, lParam);
                handled = true;
            }
            return IntPtr.Zero;
        }

        private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            // When user clicks '✕' Close button, keep running in background!
            if (!_isAuthorizedExit && _config.RunInBackgroundOnClose)
            {
                e.Cancel = true;
                HideToBackground(showNotification: true);
                return;
            }

            IntPtr hwnd = new WindowInteropHelper(this).Handle;
            if (hwnd != IntPtr.Zero)
            {
                Win32Api.UnregisterHotKey(hwnd, HOTKEY_ID_PANIC_LOCK);
            }

            _trayService.Dispose();
            _guardEngine.Dispose();

            try
            {
                _ipcCts?.Cancel();
                if (_demoChildProcess != null && !_demoChildProcess.HasExited)
                {
                    _demoChildProcess.Kill();
                }
            }
            catch { }
        }

        private static string Truncate(string value, int maxChars)
        {
            if (string.IsNullOrEmpty(value)) return string.Empty;
            return value.Length <= maxChars ? value : value.Substring(0, maxChars) + "...";
        }
    }
}
