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

' If an argument like --open is passed, or by default, open the dashboard
If WScript.Arguments.Count = 0 Or (WScript.Arguments.Count > 0 And WScript.Arguments(0) = "--open") Then
    WshShell.Run "http://127.0.0.1:3000", 1, False
End If
