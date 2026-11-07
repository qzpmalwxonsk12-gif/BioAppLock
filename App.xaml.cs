using System;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using BioAppLock.Services;

namespace BioAppLock
{
    public partial class App : Application
    {
        private const string SingleInstanceMutexName = @"Local\BioAppLock_SingleInstance_Mutex";
        private Mutex? _instanceMutex;

        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            ShutdownMode = ShutdownMode.OnExplicitShutdown;

            bool isDemoTarget = e.Args.Any(a => string.Equals(a, "--demo-target", StringComparison.OrdinalIgnoreCase));
            if (isDemoTarget)
            {
                ShutdownMode = ShutdownMode.OnMainWindowClose;
                var demoWin = new DemoTargetWindow();
                MainWindow = demoWin;
                demoWin.Show();
                return;
            }

            // Check if launched as silent self-healing background guardian: --guardian <parentPid>
            int guardianIdx = Array.FindIndex(e.Args, a => string.Equals(a, "--guardian", StringComparison.OrdinalIgnoreCase));
            if (guardianIdx >= 0 && guardianIdx + 1 < e.Args.Length && int.TryParse(e.Args[guardianIdx + 1], out int watchedPid))
            {
                RunGuardianWatchdogLoop(watchedPid);
                return;
            }

            bool isSelfTest = e.Args.Any(a => string.Equals(a, "--self-test", StringComparison.OrdinalIgnoreCase));
            bool isBackground = e.Args.Any(a => string.Equals(a, "--background", StringComparison.OrdinalIgnoreCase));

            if (!isSelfTest)
            {
                _instanceMutex = new Mutex(true, SingleInstanceMutexName, out bool createdNew);
                if (!createdNew)
                {
                    // Another instance is already running in the background! Signal it to show the dashboard.
                    try
                    {
                        using var showSignal = EventWaitHandle.OpenExisting(BioAppLock.MainWindow.ShowDashboardEventName);
                        showSignal.Set();
                    }
                    catch
                    {
                    }
                    Shutdown();
                    return;
                }
            }

            var mainWin = new MainWindow(runSelfTest: isSelfTest, startInBackground: isBackground);
            MainWindow = mainWin;

            if (isBackground && !isSelfTest)
            {
                mainWin.InitializeBackgroundSubsystem();
                mainWin.HideToBackground(showNotification: false);
            }
            else
            {
                mainWin.Show();
            }
        }

        private void RunGuardianWatchdogLoop(int watchedPid)
        {
            Task.Run(() =>
            {
                try
                {
                    using var parentProc = Process.GetProcessById(watchedPid);
                    parentProc.WaitForExit();
                }
                catch
                {
                    // Process already exited
                }

                // Check if exit was authorized via Fingerprint / PIN
                bool authorizedExit = false;
                try
                {
                    using var authSignal = EventWaitHandle.OpenExisting(BioAppLock.MainWindow.AuthorizedExitEventName);
                    authorizedExit = authSignal.WaitOne(0);
                }
                catch
                {
                }

                var config = ConfigStorageService.Load();
                if (!authorizedExit && config.KeepAliveGuardianEnabled)
                {
                    // Unauthorized termination detected -> immediately relaunch BioShield in background!
                    try
                    {
                        string exePath = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule?.FileName ?? string.Empty;
                        if (!string.IsNullOrEmpty(exePath))
                        {
                            Process.Start(new ProcessStartInfo
                            {
                                FileName = exePath,
                                Arguments = "--background",
                                UseShellExecute = false
                            });
                        }
                    }
                    catch
                    {
                    }
                }

                Dispatcher.InvokeAsync(Shutdown);
            });
        }

        protected override void OnExit(ExitEventArgs e)
        {
            try
            {
                _instanceMutex?.ReleaseMutex();
                _instanceMutex?.Dispose();
            }
            catch
            {
            }
            base.OnExit(e);
        }
    }
}
