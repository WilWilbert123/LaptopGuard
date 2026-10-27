using System.Diagnostics;
using System.Drawing;
using System.IO.Compression;
using System.Reflection;
using System.Security.Principal;
using System.Windows.Forms;
using Microsoft.Win32;

namespace GuardianInstaller;

public class InstallerForm : Form
{
    private TextBox _txtInstallDir = null!;
    private Button _btnBrowse = null!;
    private CheckBox _chkDesktopShortcut = null!;
    private CheckBox _chkStartMenu = null!;
    private CheckBox _chkAutostart = null!;
    private CheckBox _chkLaunchNow = null!;

    private Button _btnInstall = null!;
    private Button _btnCancel = null!;
    private ProgressBar _progressBar = null!;
    private Label _lblStatus = null!;

    private Panel _pnlSetup = null!;
    private Panel _pnlProgress = null!;
    private Panel _pnlComplete = null!;

    private string _installedExePath = "";

    public InstallerForm()
    {
        InitializeUi();
    }

    private void InitializeUi()
    {
        Text = "Guardian Security Setup";
        ClientSize = new Size(620, 440);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Color.FromArgb(15, 23, 42); // #0f172a Slate 900
        ForeColor = Color.FromArgb(241, 245, 249); // Slate 100

        try
        {
            string iconPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "guardian.ico");
            if (File.Exists(iconPath))
            {
                Icon = new Icon(iconPath);
            }
        }
        catch { }

        // Top Header Banner
        Panel banner = new Panel
        {
            Dock = DockStyle.Top,
            Height = 80,
            BackColor = Color.FromArgb(11, 15, 25)
        };

        Label lblHeaderTitle = new Label
        {
            Text = "GUARDIAN DEFENSE INSTALLER",
            Font = new Font("Segoe UI", 14, FontStyle.Bold),
            ForeColor = Color.FromArgb(56, 189, 248),
            Location = new Point(24, 16),
            AutoSize = true
        };

        Label lblHeaderSub = new Label
        {
            Text = "Personal Laptop Security & Threat Telemetry Monitor",
            Font = new Font("Segoe UI", 9, FontStyle.Regular),
            ForeColor = Color.FromArgb(148, 163, 184),
            Location = new Point(25, 44),
            AutoSize = true
        };

        banner.Controls.Add(lblHeaderTitle);
        banner.Controls.Add(lblHeaderSub);
        Controls.Add(banner);

        // 1. Setup Panel (Default View)
        _pnlSetup = new Panel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(25, 15, 25, 15),
            BackColor = Color.Transparent
        };

        Label lblIntro = new Label
        {
            Text = "This wizard will install Guardian Security on your Windows laptop.\nNo web browser or source code is required.",
            Font = new Font("Segoe UI", 9.5f),
            Location = new Point(25, 15),
            Size = new Size(570, 40),
            ForeColor = Color.FromArgb(226, 232, 240)
        };
        _pnlSetup.Controls.Add(lblIntro);

        Label lblDir = new Label
        {
            Text = "Destination Folder:",
            Font = new Font("Segoe UI", 9, FontStyle.Bold),
            Location = new Point(25, 65),
            AutoSize = true
        };
        _pnlSetup.Controls.Add(lblDir);

        bool isAdmin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
        string defaultDir = isAdmin
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Guardian")
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "Guardian");

        _txtInstallDir = new TextBox
        {
            Text = defaultDir,
            Location = new Point(25, 90),
            Size = new Size(465, 26),
            BackColor = Color.FromArgb(30, 41, 59),
            ForeColor = Color.White,
            BorderStyle = BorderStyle.FixedSingle,
            Font = new Font("Segoe UI", 9)
        };
        _pnlSetup.Controls.Add(_txtInstallDir);

        _btnBrowse = new Button
        {
            Text = "Browse...",
            Location = new Point(500, 89),
            Size = new Size(90, 28),
            BackColor = Color.FromArgb(51, 65, 85),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Font = new Font("Segoe UI", 9),
            Cursor = Cursors.Hand
        };
        _btnBrowse.FlatAppearance.BorderSize = 0;
        _btnBrowse.Click += (s, e) =>
        {
            using var fbd = new FolderBrowserDialog();
            fbd.SelectedPath = _txtInstallDir.Text;
            if (fbd.ShowDialog() == DialogResult.OK)
            {
                _txtInstallDir.Text = fbd.SelectedPath;
            }
        };
        _pnlSetup.Controls.Add(_btnBrowse);

        Label lblOptions = new Label
        {
            Text = "Installation Options:",
            Font = new Font("Segoe UI", 9, FontStyle.Bold),
            Location = new Point(25, 135),
            AutoSize = true
        };
        _pnlSetup.Controls.Add(lblOptions);

        _chkDesktopShortcut = new CheckBox
        {
            Text = "Create 'Guardian Security' shortcut on Desktop",
            Checked = true,
            Location = new Point(30, 160),
            Size = new Size(400, 24),
            Font = new Font("Segoe UI", 9),
            Cursor = Cursors.Hand
        };
        _pnlSetup.Controls.Add(_chkDesktopShortcut);

        _chkStartMenu = new CheckBox
        {
            Text = "Create Start Menu shortcut",
            Checked = true,
            Location = new Point(30, 190),
            Size = new Size(400, 24),
            Font = new Font("Segoe UI", 9),
            Cursor = Cursors.Hand
        };
        _pnlSetup.Controls.Add(_chkStartMenu);

        _chkAutostart = new CheckBox
        {
            Text = "Start Guardian background protection on Windows login",
            Checked = true,
            Location = new Point(30, 220),
            Size = new Size(450, 24),
            Font = new Font("Segoe UI", 9),
            Cursor = Cursors.Hand
        };
        _pnlSetup.Controls.Add(_chkAutostart);

        _btnInstall = new Button
        {
            Text = "Install Guardian",
            Location = new Point(350, 275),
            Size = new Size(130, 36),
            BackColor = Color.FromArgb(2, 132, 199),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
            Cursor = Cursors.Hand
        };
        _btnInstall.FlatAppearance.BorderSize = 0;
        _btnInstall.Click += async (s, e) => await PerformInstallAsync();
        _pnlSetup.Controls.Add(_btnInstall);

        _btnCancel = new Button
        {
            Text = "Cancel",
            Location = new Point(490, 275),
            Size = new Size(100, 36),
            BackColor = Color.FromArgb(51, 65, 85),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Font = new Font("Segoe UI", 9),
            Cursor = Cursors.Hand
        };
        _btnCancel.FlatAppearance.BorderSize = 0;
        _btnCancel.Click += (s, e) => Close();
        _pnlSetup.Controls.Add(_btnCancel);

        Controls.Add(_pnlSetup);

        // 2. Progress Panel
        _pnlProgress = new Panel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(25),
            Visible = false,
            BackColor = Color.Transparent
        };

        _lblStatus = new Label
        {
            Text = "Preparing installation...",
            Location = new Point(30, 80),
            Size = new Size(560, 30),
            Font = new Font("Segoe UI", 10, FontStyle.Regular),
            ForeColor = Color.FromArgb(226, 232, 240)
        };
        _pnlProgress.Controls.Add(_lblStatus);

        _progressBar = new ProgressBar
        {
            Location = new Point(30, 120),
            Size = new Size(560, 24),
            Style = ProgressBarStyle.Continuous,
            Value = 0
        };
        _pnlProgress.Controls.Add(_progressBar);
        Controls.Add(_pnlProgress);

        // 3. Complete Panel
        _pnlComplete = new Panel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(25),
            Visible = false,
            BackColor = Color.Transparent
        };

        Label lblSuccessTitle = new Label
        {
            Text = "Installation Complete!",
            Font = new Font("Segoe UI", 14, FontStyle.Bold),
            ForeColor = Color.FromArgb(34, 197, 94), // Green 500
            Location = new Point(30, 40),
            AutoSize = true
        };
        _pnlComplete.Controls.Add(lblSuccessTitle);

        Label lblSuccessMsg = new Label
        {
            Text = "Guardian Security has been successfully installed.\nYour laptop is now ready for local real-time threat monitoring.",
            Font = new Font("Segoe UI", 9.5f),
            ForeColor = Color.FromArgb(226, 232, 240),
            Location = new Point(30, 80),
            Size = new Size(560, 45)
        };
        _pnlComplete.Controls.Add(lblSuccessMsg);

        _chkLaunchNow = new CheckBox
        {
            Text = "Launch Guardian Security now",
            Checked = true,
            Font = new Font("Segoe UI", 10, FontStyle.Bold),
            ForeColor = Color.White,
            Location = new Point(35, 145),
            Size = new Size(300, 30),
            Cursor = Cursors.Hand
        };
        _pnlComplete.Controls.Add(_chkLaunchNow);

        Button btnFinish = new Button
        {
            Text = "Finish",
            Location = new Point(470, 275),
            Size = new Size(120, 36),
            BackColor = Color.FromArgb(2, 132, 199),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
            Cursor = Cursors.Hand
        };
        btnFinish.FlatAppearance.BorderSize = 0;
        btnFinish.Click += (s, e) =>
        {
            if (_chkLaunchNow.Checked && File.Exists(_installedExePath))
            {
                try
                {
                    Process.Start(new ProcessStartInfo(_installedExePath)
                    {
                        WorkingDirectory = Path.GetDirectoryName(_installedExePath),
                        UseShellExecute = true
                    });
                }
                catch { }
            }
            Close();
        };
        _pnlComplete.Controls.Add(btnFinish);
        Controls.Add(_pnlComplete);
    }

    private async Task PerformInstallAsync()
    {
        string targetDir = _txtInstallDir.Text.Trim();
        if (string.IsNullOrEmpty(targetDir))
        {
            MessageBox.Show("Please specify a destination folder.", "Validation Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        _pnlSetup.Visible = false;
        _pnlProgress.Visible = true;

        await Task.Run(() =>
        {
            try
            {
                UpdateProgress(10, "Terminating existing Guardian instances...");
                foreach (var p in Process.GetProcessesByName("Guardian"))
                {
                    try { p.Kill(); p.WaitForExit(1000); } catch { }
                }

                UpdateProgress(20, "Extracting application payload...");
                if (!Directory.Exists(targetDir))
                {
                    Directory.CreateDirectory(targetDir);
                }

                var assembly = Assembly.GetExecutingAssembly();
                using var stream = assembly.GetManifestResourceStream("GuardianPayload.zip");
                if (stream == null)
                {
                    throw new InvalidOperationException("Could not find embedded GuardianPayload.zip resource.");
                }

                using var archive = new ZipArchive(stream, ZipArchiveMode.Read);
                int totalEntries = archive.Entries.Count;
                int currentEntry = 0;

                foreach (var entry in archive.Entries)
                {
                    currentEntry++;
                    string destinationPath = Path.GetFullPath(Path.Combine(targetDir, entry.FullName));
                    
                    if (string.IsNullOrEmpty(entry.Name))
                    {
                        Directory.CreateDirectory(destinationPath);
                        continue;
                    }

                    string? parentDir = Path.GetDirectoryName(destinationPath);
                    if (!string.IsNullOrEmpty(parentDir) && !Directory.Exists(parentDir))
                    {
                        Directory.CreateDirectory(parentDir);
                    }

                    entry.ExtractToFile(destinationPath, true);

                    if (currentEntry % 50 == 0 || currentEntry == totalEntries)
                    {
                        int pct = 20 + (int)((float)currentEntry / totalEntries * 60);
                        UpdateProgress(pct, $"Extracting: {entry.Name} ({currentEntry}/{totalEntries})");
                    }
                }

                _installedExePath = Path.Combine(targetDir, "Guardian.exe");
                string iconPath = Path.Combine(targetDir, "guardian.ico");

                UpdateProgress(85, "Creating shortcuts...");
                if (_chkDesktopShortcut.Checked)
                {
                    string desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                    string shortcutPath = Path.Combine(desktopPath, "Guardian Security.lnk");
                    CreateShortcut(shortcutPath, _installedExePath, targetDir, iconPath, "Guardian Security & Threat Monitor");
                }

                if (_chkStartMenu.Checked)
                {
                    string programsPath = Environment.GetFolderPath(Environment.SpecialFolder.Programs);
                    string menuDir = Path.Combine(programsPath, "Guardian");
                    Directory.CreateDirectory(menuDir);
                    string shortcutPath = Path.Combine(menuDir, "Guardian.lnk");
                    CreateShortcut(shortcutPath, _installedExePath, targetDir, iconPath, "Guardian Security & Threat Monitor");
                }

                UpdateProgress(95, "Configuring Windows Startup...");
                if (_chkAutostart.Checked)
                {
                    try
                    {
                        Registry.SetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run", "GuardianSecurity", $"\"{_installedExePath}\"");
                    }
                    catch { }
                }

                UpdateProgress(100, "Installation complete!");
                Thread.Sleep(500);

                Invoke(() =>
                {
                    _pnlProgress.Visible = false;
                    _pnlComplete.Visible = true;
                });
            }
            catch (Exception ex)
            {
                Invoke(() =>
                {
                    MessageBox.Show($"Installation failed:\n{ex.Message}", "Installation Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    _pnlProgress.Visible = false;
                    _pnlSetup.Visible = true;
                });
            }
        });
    }

    private void UpdateProgress(int percentage, string status)
    {
        if (InvokeRequired)
        {
            Invoke(() => UpdateProgress(percentage, status));
            return;
        }

        _progressBar.Value = Math.Clamp(percentage, 0, 100);
        _lblStatus.Text = status;
    }

    private static void CreateShortcut(string shortcutPath, string targetPath, string workingDir, string iconLocation, string description)
    {
        try
        {
            Type? shellType = Type.GetTypeFromProgID("WScript.Shell");
            if (shellType == null) return;

            dynamic? shell = Activator.CreateInstance(shellType);
            if (shell == null) return;

            dynamic shortcut = shell.CreateShortcut(shortcutPath);
            shortcut.TargetPath = targetPath;
            shortcut.WorkingDirectory = workingDir;
            shortcut.Description = description;
            if (File.Exists(iconLocation))
            {
                shortcut.IconLocation = $"{iconLocation},0";
            }
            shortcut.Save();
        }
        catch { }
    }
}
