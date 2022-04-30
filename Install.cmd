@ECHO off
CLS
MD %ALLUSERSPROFILE%\PSSelfServiceToolkit
MD %windir%\Logs\PSSelfServiceToolkit
robocopy %~dp0 %ALLUSERSPROFILE%\PSSelfServiceToolkit *.ps1 *.xaml *.ico /z /np /LOG:%windir%\Logs\PSSelfServiceToolkit\InstallPSSelfServiceToolkit.log /tee
powershell Register-ScheduledTask -TaskName 'Start PSSelfServiceToolkit' -TaskPath 'PSSelfServiceToolkit\' -Action (New-ScheduledTaskAction -Execute 'powershell' -Argument '-NoProfile -ExecutionPolicy bypass -File %ALLUSERSPROFILE%\PSSelfServiceToolkit\SysTray.ps1') -Trigger (New-ScheduledTaskTrigger -AtLogon) -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries)
schtasks /run /tn "Start PSSelfServiceToolkit"
REG ADD HKLM\SOFTWARE\PSSelfServiceToolkit /v Version /t REG_SZ /d "1.0" /f