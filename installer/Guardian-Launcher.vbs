' =====================================================================
' GUARDIAN - Silent Windows Background Launcher
' Starts the background security worker without showing any command prompt window,
' and opens the dashboard in the default browser.
' =====================================================================

Set WshShell = CreateObject("WScript.Shell")
Set FSO = CreateObject("Scripting.FileSystemObject")

' Get Guardian root directory (parent of installer, or current directory)
ScriptDir = FSO.GetParentFolderName(WScript.ScriptFullName)
If FSO.FileExists(ScriptDir & "\background\server.js") Then
    AppDir = ScriptDir
ElseIf FSO.FileExists(ScriptDir & "\..\background\server.js") Then
    AppDir = FSO.GetAbsolutePathName(ScriptDir & "\..")
Else
    AppDir = ScriptDir
End If

' Determine Node executable: check local bin\node.exe first, then system node
NodeExe = "node.exe"
If FSO.FileExists(AppDir & "\bin\node.exe") Then
    NodeExe = AppDir & "\bin\node.exe"
End If

' Check if Guardian server is already running on port 3000
Set HTTP = CreateObject("MSXML2.ServerXMLHTTP.6.0")
On Error Resume Next
HTTP.Open "GET", "http://127.0.0.1:3000/api/status", False
HTTP.Send
If Err.Number <> 0 Then
    ' Server is not running, start it silently
    On Error GoTo 0
    RunCmd = """" & NodeExe & """ """ & AppDir & "\background\server.js"""
    WshShell.CurrentDirectory = AppDir
    WshShell.Run RunCmd, 0, False
    WScript.Sleep 1500
End If
On Error GoTo 0

' If an argument like --open is passed, or by default, open the dashboard in Native App Window mode
If WScript.Arguments.Count = 0 Or (WScript.Arguments.Count > 0 And WScript.Arguments(0) = "--open") Then
    ' Find native Chromium browser engine (Edge, Chrome, Brave) to launch as a standalone desktop window
    Dim BrowserExe, AppLaunched
    AppLaunched = False
    
    Dim Candidates(6)
    Candidates(0) = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
    Candidates(1) = "C:\Program Files\Microsoft\Edge\Application\msedge.exe"
    Candidates(2) = WshShell.ExpandEnvironmentStrings("%LOCALAPPDATA%\Microsoft\Edge\Application\msedge.exe")
    Candidates(3) = "C:\Program Files\Google\Chrome\Application\chrome.exe"
    Candidates(4) = "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
    Candidates(5) = WshShell.ExpandEnvironmentStrings("%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe")
    Candidates(6) = "C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe"
    
    For i = 0 To UBound(Candidates)
        If FSO.FileExists(Candidates(i)) Then
            BrowserExe = Candidates(i)
            Exit For
        End If
    Next
    
    If BrowserExe <> "" Then
        ' Standalone Native Application Window Mode (no address bar, no tabs, native desktop frame)
        Dim UserDataDir
        UserDataDir = WshShell.ExpandEnvironmentStrings("%LOCALAPPDATA%\Guardian\app-data")
        If Not FSO.FolderExists(WshShell.ExpandEnvironmentStrings("%LOCALAPPDATA%\Guardian")) Then
            On Error Resume Next
            FSO.CreateFolder(WshShell.ExpandEnvironmentStrings("%LOCALAPPDATA%\Guardian"))
            On Error GoTo 0
        End If
        If Not FSO.FolderExists(UserDataDir) Then
            On Error Resume Next
            FSO.CreateFolder(UserDataDir)
            On Error GoTo 0
        End If
        AppCmd = """" & BrowserExe & """ --app=http://127.0.0.1:3000 --user-data-dir=""" & UserDataDir & """ --window-size=1360,860 --no-first-run --no-default-browser-check"
        WshShell.Run AppCmd, 1, False
        AppLaunched = True
    End If
    
    ' Fallback to standard URL protocol if no Chromium browser found
    If Not AppLaunched Then
        WshShell.Run "http://127.0.0.1:3000", 1, False
    End If
End If

