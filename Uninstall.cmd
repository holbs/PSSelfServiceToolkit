@ECHO off
CLS
DEL %windir%\Logs\Flamingo /q /s > %windir%\Logs\Flamingo\Uninstall.log
schtasks /delete /tn "Start Flamingo" /f