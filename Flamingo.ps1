# A PowerShell form that can be deployed to users workstations to allow them to self heal some basic problems and get reports to assist the helpdesk when logging tickets
$ToolName        = "Flamingo"
$ToolSupport     = "heldpesk@contoso.com"
$ToolVersion     = "00.000"
$ToolLogLocation = "C:\Support\$ToolName" # Change this based on your environment
$ToolTicketUrl   = "https://helpdesk.contoso.com"

#==========================================================================#
# Import XAML file and load WPF form                                       #
#==========================================================================#

$InputXAML = (Get-Content "$PSScriptRoot\Form.xaml" -Raw).Replace('$ToolName',$ToolName).Replace('$ToolSupport',$ToolSupport).Replace('$ToolVersion',$ToolVersion)
$InputXAML = $InputXAML -Replace 'mc:Ignorable="d"','' -Replace "x:N",'N' -replace '^<Win.*','<Window'
[void][System.Reflection.Assembly]::LoadWithPartialName('PresentationFramework')
[xml]$XAML = $InputXAML
$Reader = (New-Object System.Xml.XmlNodeReader $XAML)
Try {
    $Form = [Windows.Markup.XamlReader]::Load($Reader)
} Catch {
    Write-Warning "Unable to parse XML, with error: $($Error[0]). Ensure that there are no SelectionChanged or TextChanged properties in your textboxes (PowerShell cannot process them)"
    Throw
}
$XAML.SelectNodes("//*[@Name]") | Foreach-Object {
    "Trying item $($_.Name)"
    Try {
        Set-Variable -Name "WPF$($_.Name)" -Value $Form.FindName($_.Name) -ErrorAction Stop
    } Catch {
        Throw
    }
}
Function Get-FormVariables {
    If ($Global:ReadmeDisplay -ne $true) {
        Write-Host "If you need to reference this display again, run Get-FormVariables" -ForegroundColor Yellow
        $Global:ReadmeDisplay = $true
    }
    Write-Host "Found the following interactable elements from our form" -ForegroundColor Cyan
    Get-Variable WPF*
}
Get-FormVariables
Add-Type -AssemblyName PresentationCore,PresentationFramework

#==========================================================================#
# Functions                                                                #
#==========================================================================#

Function Write-ToConsole {
    Param (
        [string] $Message,
        [switch] $NoNewLine
    )
    If ($NoNewLine.IsPresent) {
        $Form.Dispatcher.Invoke([action]{$WPFConsole.AddText($Message)},"Render")
        $Form.Dispatcher.Invoke([action]{$WPFConsole.AddText("")},"Render")
    } Else {
        $Form.Dispatcher.Invoke([action]{$WPFConsole.AddText($Message + ("`r`n"))},"Render")
        $Form.Dispatcher.Invoke([action]{$WPFConsole.AddText("")},"Render")
    }
}
Function Show-MessageBox {
    Param (
        [string] $Title,
        [string] $Body,
        [string] $Icon,
        [string] $Type
    )
    $ButtonType = [System.Windows.MessageBoxButton]::$Type
    $MessageBoxTitle = $Title
    $MessageBoxBody = $Body
    $MessageIcon = [System.Windows.MessageBoxImage]::$Icon
    [System.Windows.MessageBox]::Show($MessageBoxBody, $MessageBoxTitle, $ButtonType, $MessageIcon)
}
Function Start-AsAdministrator {
    Write-ToConsole -Message "- Restarting $ToolName as administrator"
    $ScriptPath = $($Script:MyInvocation.MyCommand.Path)
    $PowerShell = Start-Process -WindowStyle hidden -FilePath "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy bypass -File `"$ScriptPath`"" -PassThru
    Start-Sleep -Milliseconds 2000
    If (Get-Process -Id $PowerShell.Id) {
        $Form.Close()
    } Else {
        Write-ToConsole -Message "- There was a problem starting as administrator"
    }
}
Function Start-Diagnostics {
    $ClickTime = Get-Date
    $Script:Diagnostics = $true
    # Small bit of loading for pageantry
    Write-ToConsole -Message "- Running diagnostics. Please wait" -NoNewLine
    Start-Sleep -Milliseconds 500
    Write-ToConsole -Message "." -NoNewLine
    Start-Sleep -Milliseconds 500
    Write-ToConsole -Message "." -NoNewLine
    Start-Sleep -Milliseconds 500
    Write-ToConsole -Message "."
    Start-Sleep -Milliseconds 500
    # Collect some basic information first before then clearing the loading, then writing to $WPFConsole
    $DomainUser = $env:USERDOMAIN.ToUpper() + "\" + $env:USERNAME.ToLower()
    $WindowsVersion = Get-WindowsVersion
    $OfficeVersion = (Get-ChildItem -Path "$env:ProgramFiles\Microsoft Office\*","${env:ProgramFiles(x86)}\Microsoft Office\*" -Recurse | Where-Object {$_.Name -eq "Outlook.exe"} | Sort-Object -Descending LastWriteTime | Select-Object -First 1).VersionInfo.ProductVersion
    $KernelUptime = Get-KernelUptime
    $WPFConsole.Text = $null
    # Standard computer information - computer name, username, Windows version, Office version etc
    Write-ToConsole -Message "- Computer information"
    Write-ToConsole -Message ""
    Write-ToConsole -Message "ComputerName   : $($env:COMPUTERNAME.ToUpper())"
    Write-ToConsole -Message "Username       : $DomainUser"
    Write-ToConsole -Message "WindowsVersion : $WindowsVersion"
    Write-ToConsole -Message "OfficeVersion  : $OfficeVersion"
    Write-ToConsole -Message "Uptime         : $KernelUptime"
    Write-ToConsole -Message ""
    # Domain connectivity, if intranet can be reached and what server authenticated the user etc
    (& $env:WINDIR\System32\query.exe USER) -Split "\n" -Replace "\s{2,}","," | ConvertFrom-Csv | Foreach-Object {
        If (($_.Username.Trim() -Replace ('>','')) -match $env:USERNAME) {
            $LogonTimeStamp = $_.'LOGON TIME'
            $LogonTimeStamp = Get-Date $LogonTimeStamp -format "yyyy-MM-dd HH:mm:ss"
        }
    }
    Write-ToConsole -Message "- Domain connectivity"
    Write-ToConsole -Message ""
    Write-ToConsole -Message "Internet       : " -NoNewLine
    If ([Activator]::CreateInstance([Type]::GetTypeFromCLSID([GUID]'{DCB00C01-570F-4A9B-8D69-199FDBA5723B}')).IsConnectedToInternet) {
        Write-ToConsole -Message "OK"
    } Else {
        Write-ToConsole -Message "Not connected"
    }
    Write-ToConsole -Message "Intranet       : " -NoNewLine
    If (Test-Path "\\$env:USERDOMAIN\NETLOGON") {
        Write-ToConsole -Message "OK"
    } Else {
        Write-ToConsole -Message "Not connected"
    }
    Write-ToConsole -Message "LogonServer    : $env:LOGONSERVER"
    Write-ToConsole -Message "LogonTimeStamp : $(If ($LogonTimeStamp) {$LogonTimeStamp} Else {"N/A"})"
    # Network adapters, connecivity status etc
    Get-NetAdapter | Where-Object {
        $_.Name -eq "Ethernet" -or                     # Ethernet adapter
        $_.Name -like "WiFi" -or                       # WiFi adapter
        $_.InterfaceDescription -like "*PANGP*" -or    # Global Protect VPN
        $_.InterfaceDescription -like "*Juniper*"      # Pulse VPN
    } | Foreach-Object {
        Write-ToConsole -Message ""
        Write-ToConsole -Message "- $($_.Name)"
        Write-ToConsole -Message ""
        If ($_.MediaConnectionState -eq "Disconnected") {
            Write-ToConsole -Message "State          : Disconnected"
        } Elseif ($_.MediaConnectionState -eq "Connected") {
            $NetAdapter = $_
            $Connected = (Get-CimInstance Win32_NetworkAdapter | Where-Object {$_.Name -eq $NetAdapter.InterfaceDescription}).TimeOfLastReset
            $Span = New-TimeSpan -Start $Connected -End $ClickTime
            $UpTime = [string]$Span.Days + " Days " + [string]$Span.Hours + " Hours " + [string]$Span.Minutes + " Minutes " + [string]$Span.Seconds + " Seconds"
            Write-ToConsole -Message "State          : Connected"
            Write-ToConsole -Message "UpTime         : $UpTime"
            Write-ToConsole -Message "IP address     : " -NoNewLine
            Write-ToConsole -Message ($_ | Get-NetIPAddress | Where-Object {$_.AddressFamily -eq "IPv4"}).IPAddress
            Write-ToConsole -Message "MAC address    : $($_.MacAddress)"
        }
    }
    Write-ToConsole -Message ""
    # Mapped network drives. Pulled from the registry so disconnected drives are shown as well. Made into one object then added to the console
    Write-ToConsole -Message "- Network drives"
    Write-ToConsole -Message ""
    $NetworkDrives = Get-MappedNetworkDrives
    If ($NetworkDrives) {
        Write-ToConsole -Message ($NetworkDrives | Out-String).Trim()
    } Else {
        Write-ToConsole -Message "No network drives mapped"
    }
    Write-ToConsole -Message ""
    # Mapped \\network\printers. Made into one object then added to the console. Does not include local printers
    Write-ToConsole -Message "- Network printers"
    Write-ToConsole -Message ""
    $NetworkPrinters = Get-MappedNetworkPrinters
    If ($NetworkPrinters) {
        Write-ToConsole -Message ($NetworkPrinters | Out-String).Trim()
    } Else {
        Write-ToConsole -Message "No network printers mapped"
    }
    # Now note the output in a log file
    If (Test-Path $ToolLogLocation) {
        Write-Output "=============== $(Get-Date $ClickTime -format "yyyy-MM-dd") ===============" | Out-File -FilePath "$ToolLogLocation\$(Get-Date -format "yyyy-MM-dd")-$env:USERNAME-Diagnostics.log" -Force -Append
        Write-Output "" | Out-File -FilePath "$ToolLogLocation\$(Get-Date -format "yyyy-MM-dd")-$env:USERNAME-Diagnostics.log" -Force -Append
        $WPFConsole.Text | Out-File -FilePath "$ToolLogLocation\$(Get-Date -format "yyyy-MM-dd")-$env:USERNAME-Diagnostics.log" -Force -Append
    } Else {
        New-Item -Path $ToolLogLocation -ItemType Directory
        $WPFConsole.Text | Out-File -FilePath "$ToolLogLocation\$(Get-Date -format "yyyy-MM-dd")-$env:USERNAME-Diagnostics.log" -Force -Append
    }
}
Function Clear-Console {
    # Function that will clear the console if 'Start-Diagnostics' was the last function to be ran. Used to the console doesn't need to be cleared between each 'Run' function
    If ($Script:Diagnostics) {
        $WPFConsole.Text = $null
        $Script:Diagnostics = $false
    } Else {
        # Don't clear the console
    }
}
Function Invoke-ConfigMgrActions {
    $Actions = <# Hardware inventory #> "001", <# Software inventory #> "002", <# Machine policy retrieval #> "021", <# Machine policy evaluation #> "022", <# Application deployment evaluation #> "121"
    Foreach ($Action in $Actions) {
        $ConfigMgrAction = "{00000000-0000-0000-0000-000000000$Action}"
        Invoke-CimMethod -Namespace "Root\CCM" -Class "SMS_CLIENT" -Name "TriggerSchedule" -Arguments @{sScheduleID = $ConfigMgrAction}
    }
}
Function Get-KernelUptime {
    $Restarted = (Get-CimInstance -ClassName win32_operatingsystem).LastBootUpTime
    $Span = New-TimeSpan -Start $Restarted -End (Get-Date)
    $UpTime = [string]$Span.Days + " Days " + [string]$Span.Hours + " Hours " + [string]$Span.Minutes + " Minutes " + [string]$Span.Seconds + " Seconds"
    Write-Output $UpTime
}
Function Restore-NetworkDrives {
    If (Test-Path "$env:USERDOMAIN\NETLOGON") {
        $MappedDrives = Get-MappedNetworkDrives
        If ($MappedDrives) {
            # Foreach drive, check if path can be reached and the use 'net use' to unmap and remap
            $MappedDrives | Foreach-Object {
                If (Test-Path $_.Path) {
                    Write-ToConsole -Message "- Restoring $($_.Name): " -NoNewLine
                    Start-Process -WindowStyle hidden -FilePath "$env:WINDIR\System32\net.exe" -ArgumentList "use $($_.Name): /d" -Wait
                    Start-Process -WindowStyle hidden -FilePath "$env:WINDIR\System32\net.exe" -ArgumentList "use $($_.Name): \\$($_.Path) /p:y" -Wait
                    Write-ToConsole "OK"
                } Else {
                    Write-ToConsole -Message "- Restoring $($_.Name): Path not reachable. Not restored"
                }
            }
        } Else {
            Write-ToConsole -Message "- Network drives not restored. No network drives mapped"
        }
    } Else {
        Write-ToConsole -Message "- Network drives not restored. Not domain connectivity"
    }    
}
Function Get-WindowsVersion {
    # This will never match the output from winver.exe as there is no way that I know of to convert the ReleaseID to the version (21H2, 20H2, and so on)
    $Registry = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    $WinVer = "Version " + $Registry.ReleaseID + " (OS Build " + $Registry.CurrentBuild + "." + $Registry.UBR + ")"
    Write-Output $WinVer
}
Function Start-NetworkTest {
    Param (
        [string] $Command
    )
    # Get the .exe and the arguments from the command passed by splitting on empty spaces, adding .exe and creating a new array without the .exe in, then re-join to a string
    $CommandExe = ($Command -Split (' '))[0] + ".exe"
    $CommandArg = ($Command -Split (' ')) | Foreach-Object {
        If ($_ -eq ($Command -Split (' '))[0]) {
            # Do nothing as we don't want the .exe in the $CommandArg array
        } Else {
            $_
        }
    }
    $CommandArg = ($CommandArg -Join (' ') | Out-String).Trim()
    Write-ToConsole -Message "$($Command): " -NoNewLine
    Write-Output "C:\Users\$env:USERNAME> $Command" | Out-File -FilePath "$ToolLogLocation\$(Get-Date -format "yyyy-MM-dd")-$env:USERNAME-NetworkTests.log" -Force -Append
    Invoke-Expression "$env:WINDIR\System32\$CommandExe $CommandArg" | Out-File -FilePath "$ToolLogLocation\$(Get-Date -format "yyyy-MM-dd")-$env:USERNAME-NetworkTests.log" -Force -Append
    Write-ToConsole -Message "OK"
}
Function Get-MappedNetworkDrives {
    If ((Get-ChildItem -Path "REGISTRY::HKCU\Network")) {
        (Get-ChildItem -Path "REGISTRY::HKCU\Network").Name | Foreach-Object {
            $Drive = $_
            $CurrentDrive = Get-ItemProperty -Path "REGISTRY::$Drive" | Select-Object PSChildName, RemotePath
            [PSCustomObject]@{
                Name = $CurrentDrive.PSChildName.ToUpper()
                Path = $CurrentDrive.RemotePath.ToLower()
            }
        }
    } Else {
        Return $false
    }
}
Function Get-MappedNetworkPrinters {
    If ((Get-ChildItem -Path "REGISTRY::HKCU\Printers\Connections")) {
        (Get-ChildItem -Path "REGISTRY::HKCU\Printers\Connections").Name | Foreach-Object {
            $Printer = $_
            $CurrentPrinter = Get-ItemProperty -Path "REGISTRY::$Printer" | Select-Object Server, PSChildName
            [PSCustomObject]@{
                Server = $CurrentPrinter.Server.ToUpper()
                Printer = $CurrentPrinter.PSChildName.Split(',')[3].ToLower()
            }
        }
    } Else {
        Return $false
    }
}

#==========================================================================#
# Main form buttons                                                        #
#==========================================================================#

$WPFbtnDiag.Add_Click({
    # Clear the $WPFConsole box and then run Start-Diagnostics function - we always want to clear it when starting
    $WPFConsole.Text = $null
    Start-Diagnostics
})

#==========================================================================#
# File menu buttons                                                        #
#==========================================================================#

$WPFFileRefresh.Add_Click({
    # Clear the $WPFConsole box and then run Start-Diagnostics function - we always want to clear it when refreshing
    $WPFConsole.Text = $null
    Start-Diagnostics
})
$WPFFileClip.Add_Click({
    # Copy the contents of $WPFConsole to the clipboard
    $WPFConsole.Text | Set-Clipboard
})
$WPFFileSupport.Add_Click({
    # Opens the ticketing system web page - can be modified for other methods
    Start-Process -FilePath "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe" -ArgumentList $ToolTicketUrl
})
$WPFFileClose.Add_Click({
    # Close the form
    $Form.Close()
})

#==========================================================================#
# Run menu buttons                                                         #
#==========================================================================#

$WPFRunGpupdate.Add_Click({
    # Start a gpupdate in the background
    Clear-Console
    $Gpupdate = Start-Process -WindowStyle hidden -FilePath "$env:WINDIR\System32\gpupdate.exe" -ArgumentList "/force" -PassThru
    Write-ToConsole -Message "- Group Policy Update running (Process Id: $($Gpupdate.Id))"
})
$WPFRunFlushDns.Add_Click({
    # Clear the DNS cache
    Clear-Console
    Clear-DnsClientCache
    Write-ToConsole -Message "- Local DNS cache has been flushed"
})
$WPFRunIPLease.Add_Click({
    # Check if there is a DHCP server in ipconfig and if there is release the IP, renew it and then register that new IP address
    Clear-Console
    $DhcpServer = ((& $env:WINDIR\System32\ipconfig.exe /all | findstr /C:"DHCP Server") -Split ':').Trim()[1]
    If ($DhcpServer -Match '(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}') {
        # Only refresh the IP lease if there is a DHCP server detected
        Write-ToConsole -Message "- Refreshing IP lease from DHCP server '$($DhcpServer)': " -NoNewLine
        Start-Process -WindowStyle hidden -FilePath "$env:WINDIR\System32\ipconfig.exe" -ArgumentList "/release" -Wait
        Start-Process -WindowStyle hidden -FilePath "$env:WINDIR\System32\ipconfig.exe" -ArgumentList "/renew" -Wait
        Start-Process -WindowStyle hidden -FilePath "$env:WINDIR\System32\ipconfig.exe" -ArgumentList "/registerdns"
        Write-ToConsole -Message "OK"
    } Else {
        Write-ToConsole -Message "- IP lease not refreshed. No DHCP server found"
    }
})
$WPFRunKerberos.Add_Click({
    # Clear Kerberos tokens and then initiate a gpupdate back to the DC to get a new token
    Clear-Console
    If (Test-Path "\\$env:USERDOMAIN\NETLOGON") {
        Start-Process -WindowStyle hidden -FilePath "$env:WINDIR\System32\klist.exe" -ArgumentList "purge"
        Start-Process -WindowStyle hidden -FilePath "$env:WINDIR\System32\gpupdate.exe" -ArgumentList "/force"
        Write-ToConsole -Message "- Kerberos tokens refreshed"
    } Else {
        Write-ToConsole -Message "- Kerberos tokens not refreshed. No domain controller detected"
    }
})
$WPFRunSmsActions.Add_Click({
    # Runs the Hardware inventory, Software inventory, Machine policy retrieval, Machine policy evaluation, and Application deployment evaluation configuration manager cycles
    Clear-Console
    Invoke-ConfigMgrActions
    Write-ToConsole -Message "- Configuration Manager actions have been recycled. This can take some time"
})
$WPFRunRestoreDrives.Add_Click({
    # Finds mapped network drives and unmaps then and remaps them
    Clear-Console
    Restore-NetworkDrives
})
$WPFRunCheckUpdates.Add_Click({
    # Runs a check for any updates - Also uses Invoke-ConfigMgrActions function to check for updates
    Clear-Console
    Invoke-ConfigMgrActions
    Write-ToConsole -Message "- Initiated check for updates. This can take some time"
})
$WPFRunGpresult.Add_Click({
    # Generates a gpresult report in HTML in the $ToolLogLocation defined at the top of the script
    Clear-Console
    $Gpresult = Start-Process -WindowStyle hidden -FilePath "$env:WINDIR\System32\gpresult.exe" -ArgumentList "/h $ToolLogLocation\gpresult.html" -PassThru
    Write-ToConsole -Message "- Group Policy Report generating (Process Id: $($Gpresult.Id)). This can take some time"
})
$WPFRunClearTemp.Add_Click({
    # Clears %TEMP% locations that the user has access to
    Clear-Console
    Write-ToConsole -Message "- Cleaning temporary files: "
    Get-ChildItem -Path $env:TEMP -Force | Remove-Item -Force -Confirm:$false
    Write-ToConsole -Message "OK"
})
$WPFRunOutlookRefresh.Add_Click({
    # Rebuilds the Outlook profile if Outlook is not open
    Clear-Console
    $Outlook = Get-Process -Name Outlook
    If ($Outlook) {
        Write-ToConsole -Message "- Outlook still running. Cannot refresh profile"
    } Else {
        Write-ToConsole -Message "- Refreshing Outlook profile: " -NoNewLine
        $Version = (Get-ChildItem -Path "$env:ProgramFiles\Microsoft Office\*","${env:ProgramFiles(x86)}\Microsoft Office\*" -Recurse | Where-Object {$_.Name -eq "Outlook.exe"} | Sort-Object -Descending LastWriteTime)[0].VersionInfo.ProductVersion
        $Version = $Version.Split('.')[0]
        $ProfileName = "$env:USERNAME-$(Get-Date -format "yyyyMMddHHmmss")"
        Start-Process -WindowStyle hidden -FilePath "$env:WINDIR\System32\reg.exe" -ArgumentList "ADD HKCU\SOFTWARE\Microsoft\Office\$Version.0\Outlook\Profiles\$ProfileName /f" -Wait
        Start-Process -WindowStyle hidden -FilePath "$env:WINDIR\System32\reg.exe" -ArgumentList "ADD HKCU\SOFTWARE\Microsoft\Office\$Version.0\Outlook /v DefaultProfile /t REG_SZ /d $ProfileName /f"
        Write-ToConsole -Message "OK"
    }
})
$WPFRunTeamsRefresh.Add_Click({
    # Clears the Teams cache if Teams is not open. It then rebuilds on relaunch
    Clear-Console
    $Teams = Get-Process -Name Teams
    If ($Teams) {
        Write-ToConsole -Message "- Teams still running. Cannot refresh cache"
    } Else {
        Write-ToConsole -Message "- Refreshing Teams cache: " -NoNewLine
        If (Test-Path "$env:APPDATA\Microsoft\Teams.o") {
            Get-Item -Path "$env:APPDATA\Microsoft\Teams.o" -Force | Remove-Item -Recurse -Force -Confirm:$false
        }
        Get-Item -Path "$env:APPDATA\Microsoft\Teams" -Force | Rename-Item -NewName "Teams.o" -Force -Confirm:$false
        Write-ToConsole -Message "OK"
    }
})
$WPFRunClearCreds.Add_Click({
    # Clears stored credentials from Credential Manager
    Clear-Console
    $ClearCreds = @(
        "cmdkey.exe /list > %TEMP%\List.txt"
        "findstr.exe target=microsoft %TEMP%\List.txt > %TEMP%\tokensonly.txt"
        "FOR /F `"tokens=1,2 delims= `" %%G IN (%TEMP%\tokensonly.txt) DO cmdkey.exe /delete:%%H"
        "del %TEMP%\List.txt /s /f /q"
        "del %TEMP%\tokensonly.txt /s /f /q"
        "del %~f0"
    )
    $ClearCreds | Set-Content $env:TEMP\ClearCreds.cmd -Encoding Ascii
    Start-Process -WindowStyle hidden -FilePath "$env:WINDIR\System32\cmd.exe" -ArgumentList "$env:TEMP\ClearCreds.cmd"
    Write-ToConsole -Message "- Credential vault cleared"
})
$WPFRunNetworkTests.Add_Click({
    # Runs a number of network tests using the Start-NetworkTest function which captures the commands and output in a log - always clear the console and remove the old log
    If (Test-Path $ToolLogLocation) {
        Remove-Item -Path "$ToolLogLocation\$(Get-Date -format "yyyy-MM-dd")-$env:USERNAME-NetworkTests.log" -Force -Confirm:$false
    } Else {
        New-Item -Path $ToolLogLocation -ItemType Directory
    }    
    $WPFConsole.Text = $null
    Write-ToConsole -Message "- Running network tests"
    Write-ToConsole -Message ""
    Start-NetworkTest -Command "ipconfig /all"
    Start-NetworkTest -Command "ping $env:USERDOMAIN"
    Start-NetworkTest -Command "tracert $env:USERDOMAIN"
    Start-NetworkTest -Command "ping 1.1.1.1"
    Start-NetworkTest -Command "tracert 1.1.1.1"
    Start-NetworkTest -Command "arp -a"
    Start-NetworkTest -Command "netstat -an"
    Start-NetworkTest -Command "netstat -rn"
    Start-NetworkTest -Command "netsh int show int"
    Start-NetworkTest -Command "netsh wlan show int"
    Start-NetworkTest -Command "netsh advf show currentprofile"
    If (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Start-NetworkTest -Command "netsh advf monitor show mmsa"
        Start-NetworkTest -Command "netsh advf monitor show qmsa"
    } 
    Write-ToConsole -Message ""
    Write-ToConsole -Message "- Network test complete. Opening log"
    Start-Sleep -Milliseconds 1000
    Start-Process -FilePath "$env:WINDIR\System32\Notepad.exe" -ArgumentList "$ToolLogLocation\$(Get-Date -format "yyyy-MM-dd")-$env:USERNAME-NetworkTests.log"
})

#==========================================================================#
# Help menu buttons                                                        #
#==========================================================================#

$WPFHelpAdmin.Add_Click({
    # Elevates the tool to run as administrator
    Clear-Console
    If (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Write-ToConsole -Message "- Already running as administrator"
    } Else {
        Start-AsAdministrator
    }
})
$WPFHelpAbout.Add_Click({
    Show-MessageBox -Title "About" -Body "$ToolName (v$ToolVersion). Written by Aran Holbrook`n`nLinks:`n`n - https://github.com/holbs`n - https://linkedin.com/in/aranholbrook" -Icon "Information" -Type "OK"
})

#==========================================================================#
# Welcome message                                                          #
#==========================================================================#

Try {
    $ADSI = [adsisearcher]"(&(ObjectCategory=Person)(ObjectClass=User)(samaccountname=$env:USERNAME))"
    $ADUser = $ADSI.FindAll()
    Write-ToConsole -Message "- Welcome $($ADUser.Properties.givenname[0]). Click 'Start Diagnostics' to begin"
} Catch {
    Write-ToConsole -Message "- Welcome $((Get-LocalUser -Name $env:USERNAME).FullName.Split(' ')[0]). Click 'Start Diagnostics' to begin"
}
# Add the Diagnostics flag to clear the welcome screen if Clear-Console is called before Start-Diagnostics
$Script:Diagnostics = $true

#==========================================================================#
# Shows the form                                                           #
#==========================================================================#

$Form.ShowDialog() | Out-Null