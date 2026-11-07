using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using BioAppLock.Models;

namespace BioAppLock.Services
{
    public static class ConfigStorageService
    {
        private static readonly string AppDataFolder = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "BioAppLock");

        private static readonly string ConfigFilePath = Path.Combine(AppDataFolder, "config.json");

        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            WriteIndented = true
        };

        public static AppConfig Load()
        {
            try
            {
                if (File.Exists(ConfigFilePath))
                {
                    string json = File.ReadAllText(ConfigFilePath);
                    var cfg = JsonSerializer.Deserialize<AppConfig>(json, JsonOptions);
                    if (cfg != null)
                    {
                        return cfg;
                    }
                }
            }
            catch
            {
                // Ignore corrupt config and return defaults
            }

            var defaultConfig = CreateDefaultConfig();
            Save(defaultConfig);
            return defaultConfig;
        }

        public static void Save(AppConfig config)
        {
            try
            {
                Directory.CreateDirectory(AppDataFolder);
                string json = JsonSerializer.Serialize(config, JsonOptions);
                File.WriteAllText(ConfigFilePath, json);
            }
            catch
            {
            }
        }

        private static AppConfig CreateDefaultConfig()
        {
            return new AppConfig
            {
                IsMasterProtectionEnabled = true,
                LockImmediatelyOnMinimize = true,
                LockOnSwitchAway = false,
                SwitchAwayGraceSeconds = 5,
                AutoMinimizeOnLock = true,
                AllowBackupPin = false,
                BackupPin = string.Empty,
                Rules = new List<ProtectedAppRule>
                {
                    new ProtectedAppRule
                    {
                        DisplayName = "Antigravity IDE",
                        ProcessName = "Antigravity",
                        TitleKeyword = "Antigravity",
                        IsEnabled = true,
                        // Start unlocked if currently being used in foreground; locks immediately when minimized or switched away!
                        IsCurrentlyUnlocked = true
                    },
                    new ProtectedAppRule
                    {
                        DisplayName = "Confidential Demo Workspace",
                        ProcessName = "",
                        TitleKeyword = "[CONFIDENTIAL-DEMO]",
                        IsEnabled = true,
                        IsCurrentlyUnlocked = false
                    },
                    new ProtectedAppRule
                    {
                        DisplayName = "Notepad",
                        ProcessName = "notepad",
                        TitleKeyword = "Notepad",
                        IsEnabled = true,
                        IsCurrentlyUnlocked = false
                    }
                }
            };
        }
    }
}
