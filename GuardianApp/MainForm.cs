using System.Diagnostics;
using System.Drawing;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

namespace Guardian;

public class MainForm : Form
{
    private const string DashboardUrl = "http://127.0.0.1:3000";
    private const string StatusEndpoint = "http://127.0.0.1:3000/api/status";

    private WebView2 _webView = null!;
    private Panel _splashPanel = null!;
    private Label _lblTitle = null!;
    private Label _lblSubtitle = null!;
    private Label _lblStatus = null!;
    private ProgressBar _progressBar = null!;
    private Button _btnRetry = null!;
    private Button _btnLogs = null!;

    private NotifyIcon _trayIcon = null!;
    private ContextMenuStrip _trayMenu = null!;

    private Process? _engineProcess;
    private bool _isExiting = false;
    private static readonly HttpClient _httpClient = new() { Timeout = TimeSpan.FromSeconds(2) };

    public MainForm(EventWaitHandle? showEvent = null)
    {
        InitializeUi();
        SetupTray();

        if (showEvent != null)
        {
            Task.Run(() =>
            {
                while (!_isExiting)
                {
                    showEvent.WaitOne();
                    if (_isExiting) break;
                    try
                    {
                        Invoke(RestoreWindow);
                    }
                    catch { }
                }
            });
        }
    }

    private void InitializeUi()
    {
        Text = "Guardian - Personal Laptop Security & Threat Monitor";
        ClientSize = new Size(1360, 860);
        MinimumSize = new Size(1024, 680);
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Color.FromArgb(11, 15, 25); // #0b0f19 Dark theme background

        // Load Icon
        try
        {
            string iconPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "guardian.ico");
            if (File.Exists(iconPath))
            {
                Icon = new Icon(iconPath);
            }
        }
        catch { }

        // Setup Splash Panel
        _splashPanel = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = Color.FromArgb(11, 15, 25)
        };

        TableLayoutPanel layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 3,
            RowCount = 6,
            BackColor = Color.Transparent
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50F));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 450F));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50F));

        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 50F));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 50F)); // Title
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 30F)); // Subtitle
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 35F)); // Progress Bar
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 40F)); // Status label
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 50F));

        _lblTitle = new Label
        {
            Text = "GUARDIAN DEFENSE",
            ForeColor = Color.FromArgb(56, 189, 248), // Sky blue
            Font = new Font("Segoe UI", 22, FontStyle.Bold),
            TextAlign = ContentAlignment.MiddleCenter,
            Dock = DockStyle.Fill
        };

        _lblSubtitle = new Label
        {
            Text = "Personal Laptop Security & Threat Telemetry Monitor",
            ForeColor = Color.FromArgb(148, 163, 184), // Slate 400
            Font = new Font("Segoe UI", 10, FontStyle.Regular),
            TextAlign = ContentAlignment.MiddleCenter,
            Dock = DockStyle.Fill
        };

        _progressBar = new ProgressBar
        {
            Style = ProgressBarStyle.Marquee,
            MarqueeAnimationSpeed = 25,
            Dock = DockStyle.Fill,
            Height = 16
        };

        _lblStatus = new Label
        {
            Text = "Initializing security engine...",
            ForeColor = Color.FromArgb(241, 245, 249),
            Font = new Font("Segoe UI", 10, FontStyle.Regular),
            TextAlign = ContentAlignment.MiddleCenter,
            Dock = DockStyle.Fill
        };

        FlowLayoutPanel btnPanel = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false
        };

        _btnRetry = new Button
        {
            Text = "Retry Launch",
            Size = new Size(130, 36),
            BackColor = Color.FromArgb(2, 132, 199),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Font = new Font("Segoe UI", 9, FontStyle.Bold),
            Visible = false,
            Cursor = Cursors.Hand
        };
        _btnRetry.FlatAppearance.BorderSize = 0;
        _btnRetry.Click += async (s, e) => await StartEngineAndNavigateAsync();

        _btnLogs = new Button
        {
            Text = "Open Logs Folder",
            Size = new Size(130, 36),
            BackColor = Color.FromArgb(30, 41, 59),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Font = new Font("Segoe UI", 9, FontStyle.Regular),
            Visible = false,
            Cursor = Cursors.Hand
        };
        _btnLogs.FlatAppearance.BorderSize = 0;
        _btnLogs.Click += (s, e) => OpenDataFolder();

        btnPanel.Controls.Add(_btnRetry);
        btnPanel.Controls.Add(_btnLogs);

        layout.Controls.Add(_lblTitle, 1, 1);
        layout.Controls.Add(_lblSubtitle, 1, 2);
        layout.Controls.Add(_progressBar, 1, 3);
        layout.Controls.Add(_lblStatus, 1, 4);

        _splashPanel.Controls.Add(layout);
        Controls.Add(_splashPanel);

        // Setup WebView2 control (initially hidden)
        _webView = new WebView2
        {
            Dock = DockStyle.Fill,
            Visible = false
        };
        Controls.Add(_webView);

        FormClosing += MainForm_FormClosing;
        Shown += async (s, e) => await StartEngineAndNavigateAsync();
    }

    private void SetupTray()
    {
        _trayMenu = new ContextMenuStrip();
        
        var titleItem = new ToolStripMenuItem("Guardian Security (Active)")
        {
            Enabled = false,
            Font = new Font("Segoe UI", 9, FontStyle.Bold)
        };
        _trayMenu.Items.Add(titleItem);
        _trayMenu.Items.Add(new ToolStripSeparator());

        var openItem = new ToolStripMenuItem("Open Dashboard", null, (s, e) => RestoreWindow());
        openItem.Font = new Font("Segoe UI", 9, FontStyle.Bold);
        _trayMenu.Items.Add(openItem);

        var restartItem = new ToolStripMenuItem("Restart Security Engine", null, async (s, e) => await RestartEngineAsync());
        _trayMenu.Items.Add(restartItem);

        _trayMenu.Items.Add(new ToolStripSeparator());

        var exitItem = new ToolStripMenuItem("Exit Guardian", null, (s, e) => ExitApplication());
        _trayMenu.Items.Add(exitItem);

        _trayIcon = new NotifyIcon
        {
            Text = "Guardian Security",
            ContextMenuStrip = _trayMenu,
            Visible = true
        };

        if (Icon != null)
        {
            _trayIcon.Icon = Icon;
        }

        _trayIcon.DoubleClick += (s, e) => RestoreWindow();
    }

    public void RestoreWindow()
    {
        if (InvokeRequired)
        {
            Invoke(RestoreWindow);
            return;
        }
        Show();
        WindowState = FormWindowState.Normal;
        BringToFront();
        Activate();
        TopMost = true;
        TopMost = false;
    }

    private void ExitApplication()
    {
        _isExiting = true;
        _trayIcon.Visible = false;
        KillEngineProcess();
        Application.Exit();
    }

    private void MainForm_FormClosing(object? sender, FormClosingEventArgs e)
    {
        if (!_isExiting && e.CloseReason == CloseReason.UserClosing)
        {
            e.Cancel = true;
            Hide();
            _trayIcon.ShowBalloonTip(
                2500,
                "Guardian Security",
                "Guardian is actively protecting your laptop in the background. Click the tray icon to open anytime.",
                ToolTipIcon.Info
            );
        }
        else
        {
            KillEngineProcess();
        }
    }

    private async Task StartEngineAndNavigateAsync()
    {
        _btnRetry.Visible = false;
        _btnLogs.Visible = false;
        _progressBar.Visible = true;
        _lblStatus.Text = "Checking background security engine...";

        try
        {
            // 1. Check if engine is already up
            bool isRunning = await IsEngineRespondingAsync();

            if (!isRunning)
            {
                _lblStatus.Text = "Starting background security engine...";
                StartEngineProcess();

                // Wait up to 15 seconds for HTTP 200 OK
                int attempts = 0;
                while (attempts < 50)
                {
                    await Task.Delay(300);
                    attempts++;
                    _lblStatus.Text = $"Starting telemetry engine (waiting {attempts * 300 / 1000}s)...";

                    if (await IsEngineRespondingAsync())
                    {
                        isRunning = true;
                        break;
                    }
                }
            }

            if (!isRunning)
            {
                _progressBar.Visible = false;
                _lblStatus.Text = "Security engine could not be contacted.\nPlease check Node.js or click Retry.";
                _btnRetry.Visible = true;
                _btnLogs.Visible = true;
                return;
            }

            _lblStatus.Text = "Loading security dashboard...";

            // Initialize WebView2
            string userDataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Guardian", "WebView2Data");
            Directory.CreateDirectory(userDataDir);

            var env = await CoreWebView2Environment.CreateAsync(null, userDataDir);
            await _webView.EnsureCoreWebView2Async(env);

            _webView.CoreWebView2.Settings.IsStatusBarEnabled = false;
            _webView.CoreWebView2.Settings.AreDefaultContextMenusEnabled = true;

            _webView.NavigationCompleted += (s, args) =>
            {
                _splashPanel.Visible = false;
                _webView.Visible = true;
            };

            _webView.Source = new Uri(DashboardUrl);
        }
        catch (Exception ex)
        {
            _progressBar.Visible = false;
            _lblStatus.Text = $"Initialization error: {ex.Message}";
            _btnRetry.Visible = true;
            _btnLogs.Visible = true;
        }
    }

    private async Task<bool> IsEngineRespondingAsync()
    {
        try
        {
            var res = await _httpClient.GetAsync(StatusEndpoint);
            return res.IsSuccessStatusCode;
        }
        catch
        {
            return false;
        }
    }

    private void StartEngineProcess()
    {
        string baseDir = AppDomain.CurrentDomain.BaseDirectory;

        // Locate node.exe
        string? nodeExe = null;
        string[] nodeCandidates = [
            Path.Combine(baseDir, "bin", "node.exe"),
            Path.Combine(baseDir, "engine", "bin", "node.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "nodejs", "node.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "nodejs", "node.exe")
        ];

        foreach (var c in nodeCandidates)
        {
            if (File.Exists(c))
            {
                nodeExe = c;
                break;
            }
        }

        if (nodeExe == null)
        {
            nodeExe = "node.exe"; // Fallback to system PATH
        }

        // Locate server.js
        string[] serverCandidates = [
            Path.Combine(baseDir, "background", "server.js"),
            Path.Combine(baseDir, "engine", "background", "server.js"),
            Path.Combine(baseDir, "..", "background", "server.js"),
            Path.Combine(baseDir, "..", "..", "background", "server.js"),
            Path.Combine(baseDir, "..", "..", "..", "background", "server.js")
        ];

        string? serverJs = null;
        string? workingDir = null;

        foreach (var sc in serverCandidates)
        {
            string full = Path.GetFullPath(sc);
            if (File.Exists(full))
            {
                serverJs = full;
                workingDir = Path.GetDirectoryName(Path.GetDirectoryName(full));
                break;
            }
        }

        if (serverJs == null || workingDir == null)
        {
            throw new FileNotFoundException("Could not locate background/server.js in application directory.");
        }

        // Ensure working directory has .env and data folder
        try
        {
            string envPath = Path.Combine(workingDir, ".env");
            string envExample = Path.Combine(workingDir, ".env.example");
            if (!File.Exists(envPath) && File.Exists(envExample))
            {
                File.Copy(envExample, envPath, true);
            }
            string dataPath = Path.Combine(workingDir, "data");
            if (!Directory.Exists(dataPath))
            {
                Directory.CreateDirectory(dataPath);
            }
        }
        catch { }

        string logDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Guardian");
        string logPath = Path.Combine(logDir, "engine.log");
        try
        {
            Directory.CreateDirectory(logDir);
            File.AppendAllText(logPath, $"\n--- [{DateTime.Now:yyyy-MM-dd HH:mm:ss}] Launching {nodeExe} {serverJs} ---\n");
        }
        catch { }

        var psi = new ProcessStartInfo
        {
            FileName = nodeExe,
            Arguments = $"\"{serverJs}\"",
            WorkingDirectory = workingDir,
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WindowStyle = ProcessWindowStyle.Hidden
        };

        try
        {
            _engineProcess = new Process { StartInfo = psi, EnableRaisingEvents = true };
            _engineProcess.OutputDataReceived += (s, e) =>
            {
                if (e.Data != null)
                {
                    try { File.AppendAllText(logPath, $"[OUT] {e.Data}\n"); } catch { }
                }
            };
            _engineProcess.ErrorDataReceived += (s, e) =>
            {
                if (e.Data != null)
                {
                    try { File.AppendAllText(logPath, $"[ERR] {e.Data}\n"); } catch { }
                }
            };

            _engineProcess.Start();
            _engineProcess.BeginOutputReadLine();
            _engineProcess.BeginErrorReadLine();
        }
        catch (Exception ex)
        {
            try { File.AppendAllText(logPath, $"[CRASH] {ex}\n"); } catch { }
            throw new InvalidOperationException($"Failed to launch engine ({nodeExe}): {ex.Message}", ex);
        }
    }

    private async Task RestartEngineAsync()
    {
        _splashPanel.Visible = true;
        _webView.Visible = false;
        _lblStatus.Text = "Restarting security engine...";
        KillEngineProcess();
        await Task.Delay(1000);
        await StartEngineAndNavigateAsync();
    }

    private void KillEngineProcess()
    {
        try
        {
            if (_engineProcess != null && !_engineProcess.HasExited)
            {
                _engineProcess.Kill(true);
                _engineProcess.Dispose();
                _engineProcess = null;
            }
        }
        catch { }
    }

    private void OpenDataFolder()
    {
        try
        {
            string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Guardian");
            if (!Directory.Exists(path))
            {
                path = AppDomain.CurrentDomain.BaseDirectory;
            }
            Process.Start(new ProcessStartInfo("explorer.exe", path) { UseShellExecute = true });
        }
        catch { }
    }
}
