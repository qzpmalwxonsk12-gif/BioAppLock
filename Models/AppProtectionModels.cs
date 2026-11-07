using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace BioAppLock.Models
{
    public class ProtectedAppRule : INotifyPropertyChanged
    {
        private string _id = Guid.NewGuid().ToString("N");
        private string _displayName = string.Empty;
        private string _processName = string.Empty;
        private string _titleKeyword = string.Empty;
        private bool _isEnabled = true;
        private bool _isCurrentlyUnlocked = false;
        private DateTime? _unlockedAt = null;
        private DateTime? _lastUnfocusedAt = null;
        private int _blockedAttempts = 0;

        public string Id
        {
            get => _id;
            set { _id = value; OnPropertyChanged(); }
        }

        public string DisplayName
        {
            get => _displayName;
            set { _displayName = value; OnPropertyChanged(); }
        }

        /// <summary>
        /// Process name without .exe (e.g. "Antigravity", "chrome", "notepad")
        /// </summary>
        public string ProcessName
        {
            get => _processName;
            set { _processName = value; OnPropertyChanged(); }
        }

        /// <summary>
        /// Optional window title substring match (e.g. "Antigravity", "WhatsApp")
        /// </summary>
        public string TitleKeyword
        {
            get => _titleKeyword;
            set { _titleKeyword = value; OnPropertyChanged(); }
        }

        public bool IsEnabled
        {
            get => _isEnabled;
            set
            {
                _isEnabled = value;
                if (!_isEnabled)
                {
                    IsCurrentlyUnlocked = false;
                }
                OnPropertyChanged();
                OnPropertyChanged(nameof(StatusText));
                OnPropertyChanged(nameof(StatusColor));
            }
        }

        [System.Text.Json.Serialization.JsonIgnore]
        public bool IsCurrentlyUnlocked
        {
            get => _isCurrentlyUnlocked;
            set
            {
                _isCurrentlyUnlocked = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(StatusText));
                OnPropertyChanged(nameof(StatusColor));
            }
        }

        [System.Text.Json.Serialization.JsonIgnore]
        public DateTime? UnlockedAt
        {
            get => _unlockedAt;
            set { _unlockedAt = value; OnPropertyChanged(); }
        }

        [System.Text.Json.Serialization.JsonIgnore]
        public DateTime? LastUnfocusedAt
        {
            get => _lastUnfocusedAt;
            set { _lastUnfocusedAt = value; OnPropertyChanged(); }
        }

        public int BlockedAttempts
        {
            get => _blockedAttempts;
            set { _blockedAttempts = value; OnPropertyChanged(); }
        }

        [System.Text.Json.Serialization.JsonIgnore]
        public string StatusText
        {
            get
            {
                if (!IsEnabled) return "PAUSED";
                return IsCurrentlyUnlocked ? "UNLOCKED (ACTIVE)" : "LOCKED (ARMED)";
            }
        }

        [System.Text.Json.Serialization.JsonIgnore]
        public string StatusColor
        {
            get
            {
                if (!IsEnabled) return "#64748B";
                return IsCurrentlyUnlocked ? "#10B981" : "#F59E0B";
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string? name = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }

    public class RunningWindowItem
    {
        public IntPtr Hwnd { get; set; }
        public uint ProcessId { get; set; }
        public string ProcessName { get; set; } = string.Empty;
        public string WindowTitle { get; set; } = string.Empty;
        public bool IsMinimized { get; set; }
        public string StateLabel => IsMinimized ? "Minimized" : "Open";
        public string Summary => $"{ProcessName}.exe — {WindowTitle}";
    }

    public class SecurityAuditEntry
    {
        public DateTime Timestamp { get; set; } = DateTime.Now;
        public string TimeFormatted => Timestamp.ToString("HH:mm:ss");
        public string EventType { get; set; } = string.Empty; // INTERCEPTED, VERIFIED, BLOCKED, RELOCKED
        public string AppName { get; set; } = string.Empty;
        public string Details { get; set; } = string.Empty;
        public string BadgeColor => EventType switch
        {
            "VERIFIED" => "#10B981",
            "BLOCKED" => "#EF4444",
            "INTERCEPTED" => "#F59E0B",
            _ => "#3B82F6"
        };
    }

    public class AppConfig
    {
        public bool IsMasterProtectionEnabled { get; set; } = true;
        public bool LockImmediatelyOnMinimize { get; set; } = true;
        public bool LockOnSwitchAway { get; set; } = true;
        public int SwitchAwayGraceSeconds { get; set; } = 3;
        public bool AutoMinimizeOnLock { get; set; } = true;
        public bool AllowBackupPin { get; set; } = true;
        public string BackupPin { get; set; } = "1234";
        public bool RunInBackgroundOnClose { get; set; } = true;
        public bool KeepAliveGuardianEnabled { get; set; } = true;
        public bool StartWithWindows { get; set; } = true;
        public bool ProtectSelfDashboard { get; set; } = false;
        public List<ProtectedAppRule> Rules { get; set; } = new();
    }
}
