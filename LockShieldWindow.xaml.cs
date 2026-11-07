using System;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using BioAppLock.Models;
using BioAppLock.Services;

namespace BioAppLock
{
    public partial class LockShieldWindow : Window
    {
        private readonly ProtectedAppRule _rule;
        private readonly IntPtr _targetHwnd;
        private readonly string _windowTitle;
        private readonly AppConfig _config;
        private CancellationTokenSource? _helloCts;
        private bool _isVerifying = false;

        public bool IsAuthenticated { get; private set; } = false;
        public string AuthMethod { get; private set; } = string.Empty;

        public LockShieldWindow(
            ProtectedAppRule rule,
            IntPtr targetHwnd,
            string windowTitle,
            AppConfig config)
        {
            InitializeComponent();

            _rule = rule;
            _targetHwnd = targetHwnd;
            _windowTitle = string.IsNullOrWhiteSpace(windowTitle) ? rule.DisplayName : windowTitle;
            _config = config;

            AppNameText.Text = string.IsNullOrWhiteSpace(rule.DisplayName)
                ? $"{rule.ProcessName}.exe"
                : rule.DisplayName;

            WindowDetailsText.Text = $"Process: {rule.ProcessName}.exe • Window: \"{_windowTitle}\"";

            BackupPinPanel.Visibility = _config.AllowBackupPin
                ? Visibility.Visible
                : Visibility.Collapsed;
        }

        private async void Window_Loaded(object sender, RoutedEventArgs e)
        {
            if (_targetHwnd != IntPtr.Zero && !Win32Api.IsIconic(_targetHwnd))
            {
                Win32Api.ForceMinimizeWindow(_targetHwnd);
            }

            IntPtr shieldHwnd = new WindowInteropHelper(this).Handle;
            Win32Api.ForceRestoreAndFocusWindow(shieldHwnd);
            Activate();
            Focus();

            // Wait briefly for taskbar mouse-release events to settle before spawning Windows Security
            await Task.Delay(160);
            await TriggerWindowsHelloVerificationAsync();
        }

        public async Task TriggerWindowsHelloVerificationAsync()
        {
            if (_isVerifying || !IsLoaded) return;
            _isVerifying = true;

            _helloCts?.Cancel();
            _helloCts = new CancellationTokenSource();

            try
            {
                VerifyHelloButton.IsEnabled = false;
                VerifyButtonLabel.Text = "Waiting for Windows Hello Fingerprint / PIN...";
                SetBannerState(
                    "🔍 Windows Security prompt active — Touch your Fingerprint sensor or enter your Laptop PIN...",
                    "#172554", "#1D4ED8", "#93C5FD");

                if (_targetHwnd != IntPtr.Zero && !Win32Api.IsIconic(_targetHwnd))
                {
                    Win32Api.ForceMinimizeWindow(_targetHwnd);
                }

                IntPtr shieldHwnd = new WindowInteropHelper(this).Handle;
                string promptMessage = $"BioShield App Guard: Verify identity to view '{_rule.DisplayName}' ({_rule.ProcessName}.exe)";

                HelloVerificationResult result = await WindowsHelloService.RequestVerificationAsync(
                    shieldHwnd,
                    promptMessage,
                    _helloCts.Token,
                    shouldEnforceFocus: () =>
                    {
                        try
                        {
                            return Dispatcher.Invoke(() => IsLoaded && !PinPasswordBox.IsKeyboardFocusWithin);
                        }
                        catch
                        {
                            return true;
                        }
                    });

                if (result == HelloVerificationResult.Verified)
                {
                    CompleteUnlock("Windows Hello (Fingerprint / PIN)");
                    return;
                }

                string reason = result switch
                {
                    HelloVerificationResult.Canceled => "Verification was canceled. Click below to scan Fingerprint / PIN again, or Cancel to keep the app minimized.",
                    HelloVerificationResult.RetriesExhausted => "Too many failed biometric/PIN attempts.",
                    HelloVerificationResult.DeviceNotPresent => "Windows Hello biometric/PIN device not detected. Use Backup PIN below.",
                    HelloVerificationResult.NotConfiguredForUser => "Windows Hello is not configured for this Windows account. Use Backup PIN below.",
                    _ => $"Authentication not completed ({result}). Please try again."
                };

                SetBannerState($"⚠️ {reason}", "#3B0712", "#BE123C", "#FDA4AF");
            }
            finally
            {
                _isVerifying = false;
                if (IsLoaded)
                {
                    VerifyHelloButton.IsEnabled = true;
                    VerifyButtonLabel.Text = "Scan Fingerprint / Windows Hello PIN Again";
                }
            }
        }

        private async void VerifyHelloButton_Click(object sender, RoutedEventArgs e)
        {
            await TriggerWindowsHelloVerificationAsync();
        }

        private void UnlockWithPinButton_Click(object sender, RoutedEventArgs e)
        {
            TryUnlockWithBackupPin();
        }

        private void PinPasswordBox_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                TryUnlockWithBackupPin();
            }
        }

        private void TryUnlockWithBackupPin()
        {
            if (!_config.AllowBackupPin) return;

            string entered = PinPasswordBox.Password?.Trim() ?? string.Empty;
            if (!string.IsNullOrEmpty(_config.BackupPin) && entered == _config.BackupPin)
            {
                CompleteUnlock("BioShield Backup PIN");
            }
            else
            {
                PinPasswordBox.Clear();
                SetBannerState("❌ Invalid Backup PIN. Please scan your Fingerprint / Windows PIN or enter the valid Backup PIN.", "#3B0712", "#BE123C", "#FDA4AF");
            }
        }

        public void CompleteUnlock(string method)
        {
            try
            {
                _helloCts?.Cancel();
            }
            catch { }

            IsAuthenticated = true;
            AuthMethod = method;
            Close();
        }

        private void CancelLockButton_Click(object sender, RoutedEventArgs e)
        {
            CancelAndKeepMinimized();
        }

        private void Window_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Escape)
            {
                CancelAndKeepMinimized();
            }
        }

        private void CancelAndKeepMinimized()
        {
            try
            {
                _helloCts?.Cancel();
            }
            catch { }

            if (_targetHwnd != IntPtr.Zero)
            {
                Win32Api.ForceMinimizeWindow(_targetHwnd);
            }

            IsAuthenticated = false;
            Close();
        }

        private void SetBannerState(string message, string bgHex, string borderHex, string fgHex)
        {
            StatusMessageText.Text = message;
            StatusBanner.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString(bgHex));
            StatusBanner.BorderBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(borderHex));
            StatusMessageText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(fgHex));
        }
    }
}
