# BioAppLock — BioShield App Guard

A Windows desktop prototype that places a guard/shield in front of selected application windows and requests Windows Hello verification before returning to them. The WPF dashboard calls the project **BioShield App Guard**; its source/project name is **BioAppLock**.

It is an application-window privacy guard, not a replacement for Windows sign-in, file encryption, account permissions or the operating system's security boundary.

## Features represented in the source

- Rules matched by process name and optional window-title text.
- Foreground/minimise event hooks and a watchdog for protected windows.
- Windows Hello availability checks and native verification requests.
- Configurable minimise/switch-away relocking behaviour and a grace period.
- A dashboard, a confidential-demo window and an in-memory audit list.
- Tray controls, optional background-on-close behaviour and startup/guardian settings.
- A **Ctrl+Alt+L** lock/minimise action for protected apps.

Windows Hello uses whatever verification method Windows makes available for the signed-in user. The code does not independently implement a fingerprint database or guarantee a particular biometric method on every computer.

## Requirements

- Windows desktop and a usable Windows Hello configuration for Hello verification.
- **.NET 10 SDK** with Windows desktop/WPF support to build from source.
- A writable per-user application-data folder for configuration.

The project targets `net10.0-windows`; see [BioAppLock.csproj](BioAppLock.csproj). An application running with elevated privileges or in a different desktop/session may not behave like the ordinary windows used during development.

## Build and run

From the repository root:

```powershell
dotnet restore BioAppLock.csproj
dotnet build BioAppLock.csproj -c Release
dotnet run --project BioAppLock.csproj -c Release
```

To create a local Windows x64 publish folder:

```powershell
dotnet publish BioAppLock.csproj -c Release -r win-x64 --self-contained true
```

Generated `bin`/`obj` output and a packaged executable are not included in the source snapshot.

## First-use workflow

1. Start the dashboard and review Windows Hello availability.
2. Inspect the sample rules and choose which process/title combinations you actually want guarded.
3. Review the relock, backup-PIN, background and startup options before enabling them.
4. Use the demo window first, then check normal open/minimise/switch-away behaviour for each real app.
5. Use the tray menu to reopen the dashboard or exit completely. Closing the dashboard can leave the guard running when the corresponding option is enabled.

## Configuration and security limits

Configuration is written to `%LOCALAPPDATA%/BioAppLock/config.json`. The prototype contains a **default backup PIN of `1234`**, and the backup PIN is stored as readable configuration data. Review/change or disable that fallback before relying on the guard. The app does not turn its local JSON file into a protected credential store.

A process-level overlay/guard can be affected by termination, privileges, desktop changes and application window behaviour. Startup/guardian options do not make it a tamper-proof Windows service. Keep those limitations separate from the native Windows Hello prompt itself.

## Source layout

| Path | Purpose |
|---|---|
| `MainWindow.xaml` / `.cs` | Dashboard, rule editing and controls |
| `LockShieldWindow.xaml` / `.cs` | Guard/verification UI |
| `Models/AppProtectionModels.cs` | Rule, configuration, window and audit data models |
| `Services/WindowGuardEngine.cs` | Window event monitoring and guard state |
| `Services/WindowsHelloService.cs` | Native Windows Hello interop |
| `Services/ConfigStorageService.cs` | Per-user JSON persistence |
| `Services/SystemTrayAndStartupService.cs` | Tray/startup helpers |

## Validation and source completeness

The required C# model file was restored after the original backup filter accidentally excluded its `Models` folder. An isolated Release build with that restored file completed with **0 warnings and 0 errors** during this documentation update. This is a compile check, not a new biometric, background-guard or adversarial-security test.

Local user configuration and build output are excluded from the repository. No standalone project license is supplied by this README.
