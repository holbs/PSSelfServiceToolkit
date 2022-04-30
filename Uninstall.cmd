@ECHO off
CLS
schtasks /delete /tn "Start PSSelfServiceToolkit" /f
RD %ALLUSERSPROFILE%\PSSelfServiceToolkit /q /s
REG DELETE HKLM\SOFTWARE\PSSelfServiceToolkit /f