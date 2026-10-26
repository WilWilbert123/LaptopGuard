; =====================================================================
; GUARDIAN - Inno Setup Windows Installer Script
; Compiles a professional standalone "Guardian-Setup.exe" wizard
; =====================================================================

#define MyAppName "Guardian"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Guardian Security"
#define MyAppURL "http://127.0.0.1:3000"
#define MyAppExeName "Guardian-Launcher.vbs"

[Setup]
AppId={{74B9E3A2-8921-4F91-9128-B4F81711739C}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\Guardian
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
OutputDir=..\dist
OutputBaseFilename=Guardian-Setup-v{#MyAppVersion}
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64

SetupIconFile=guardian.ico

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "autostart"; Description: "Automatically start Guardian on Windows logon"; GroupDescription: "Startup Options:"

[Files]
Source: "..\background\*"; DestDir: "{app}\background"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\public\*"; DestDir: "{app}\public"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\node_modules\*"; DestDir: "{app}\node_modules"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\installer\*"; DestDir: "{app}\installer"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\package.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\.env.example"; DestDir: "{app}"; DestName: ".env"; Flags: onlyifdoesntexist

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "wscript.exe"; Parameters: """{app}\installer\Guardian-Launcher.vbs"" --open"; WorkingDir: "{app}"; IconFilename: "{app}\installer\guardian.ico"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName} Security"; Filename: "wscript.exe"; Parameters: """{app}\installer\Guardian-Launcher.vbs"" --open"; WorkingDir: "{app}"; IconFilename: "{app}\installer\guardian.ico"; Tasks: desktopicon

[Run]
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""$Action = New-ScheduledTaskAction -Execute 'wscript.exe' -Argument '\""""{app}\installer\Guardian-Launcher.vbs\"""" --daemon' -WorkingDirectory '{app}'; $Trigger = New-ScheduledTaskTrigger -AtLogOn; $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable; Register-ScheduledTask -TaskName 'Guardian_BackgroundWorker' -Action $Action -Trigger $Trigger -Settings $Settings -RunLevel HighestAvailable -Force"""; Flags: runhidden; Tasks: autostart
Filename: "wscript.exe"; Parameters: """{app}\installer\Guardian-Launcher.vbs"" --open"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""Unregister-ScheduledTask -TaskName 'Guardian_BackgroundWorker' -Confirm:$false -ErrorAction SilentlyContinue; Get-NetTCPConnection -LocalPort 3000 -State Listen -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }"""; Flags: runhidden
