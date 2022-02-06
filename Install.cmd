@ECHO off
CLS
MD %ALLUSERSPROFILE%\Flamingo
MD %windir%\Logs\Flamingo
robocopy %~dp0 %ALLUSERSPROFILE%\Flamingo *.ps1 *.xaml *.ico /z /np /LOG:%windir%\Logs\Flamingo\Install.log /tee
schtasks /create /tn "Start Flamingo" /tr "powershell -ExecutionPolicy ByPass -File %ALLUSERSPROFILE%\Flamingo\SysTray.ps1" /sc onlogon /f
schtasks /run /tn "Start Flamingo"