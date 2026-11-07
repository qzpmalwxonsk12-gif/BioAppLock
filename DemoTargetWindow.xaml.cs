using System;
using System.Windows;
using System.Windows.Threading;

namespace BioAppLock
{
    public partial class DemoTargetWindow : Window
    {
        private readonly DispatcherTimer _workTimer;
        private readonly DateTime _startedAt = DateTime.Now;
        private int _iteration = 1;

        public DemoTargetWindow()
        {
            InitializeComponent();

            _workTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromMilliseconds(500)
            };
            _workTimer.Tick += (_, _) =>
            {
                _iteration++;
                var elapsed = DateTime.Now - _startedAt;
                TaskProgressText.Text = $"Iteration #{_iteration} • Running important task in background... (Elapsed: {elapsed:mm\\:ss})";
                TaskProgressBar.Value = (_iteration * 7) % 100;
            };
            _workTimer.Start();
        }

        private void MinimizeTestButton_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState.Minimized;
        }

        private void CloseDemoButton_Click(object sender, RoutedEventArgs e)
        {
            _workTimer.Stop();
            Close();
        }
    }
}
