@ECHO off
CLS
MD %ALLUSERSPROFILE%\Flamingo
MD %windir%\Logs\Flamingo
robocopy %~dp0 %ALLUSERSPROFILE%\Flamingo *.ps1 *.xaml *.ico /z /np /LOG:%windir%\Logs\Flamingo\Install.log /tee
powershell Register-ScheduledTask -TaskName 'Start Flamingo' -Action (New-ScheduledTaskAction -Execute 'powershell' -Argument '-NoProfile -ExecutionPolicy bypass -File %ALLUSERSPROFILE%\Flamingo\SysTray.ps1') -Trigger (New-ScheduledTaskTrigger -AtLogon) -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries)
schtasks /run /tn "Start Flamingo"
REG ADD HKLM\SOFTWARE\Flamingo /v Version /t REG_SZ /d "1.0" /f