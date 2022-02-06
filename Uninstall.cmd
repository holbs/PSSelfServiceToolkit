@ECHO off
CLS
schtasks /delete /tn "Start Flamingo" /f
REG DELETE HKLM\SOFTWARE\Flamingo /f