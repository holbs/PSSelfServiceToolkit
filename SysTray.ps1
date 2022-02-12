# A set of PowerShell scripts can be deployed to Windows workstations to allow for users to self heal
$ToolName      = "Flamingo"
$ToolTicketUrl = "https://helpdesk.contoso.local/"

# Create a Start Menu shortcut that opens Flamingo
$Shell = New-Object -ComObject WScript.Shell
$Shortcut = $Shell.CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Flamingo.lnk")
$Shortcut.TargetPath = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
$Shortcut.Arguments = "-WindowStyle hidden -NoProfile -ExecutionPolicy bypass -File `"$env:ProgramData\Flamingo\Flamingo.ps1`""
$Shortcut.WorkingDirectory = "$env:WINDIR\System32\WindowsPowerShell\v1.0\"
$Shortcut.IconLocation = "$env:ProgramData\Flamingo\Icon.ico,0"
$Shortcut.Save()

# Create the form for the System Tray icon (also known as NotifyIcon)
[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
[System.Reflection.Assembly]::LoadWithPartialName('PresentationFramework')
[System.Reflection.Assembly]::LoadWithPartialName('System.Drawing')
[System.Reflection.Assembly]::LoadWithPartialName('WindowsFormsIntegration')
 
$Icon = New-Object System.Drawing.Icon ("$PSScriptRoot\Icon.ico")
$SysTray = New-Object System.Windows.Forms.NotifyIcon
$SysTray.Text = $ToolName
$SysTray.Icon = $Icon
$SysTray.Visible = $true
 
# Selections text seen when right clicking the system tray icon
$ContextOpen = New-Object System.Windows.Forms.MenuItem
$ContextOpen.Text = "Open"
# The below could be the links from the form, or the run actions, or both, or something else completely
$ContextSupport = New-Object System.Windows.Forms.MenuItem
$ContextSupport.Text = "Contact Support"
# The Exit will close the system tray tool
$ContextExit = New-Object System.Windows.Forms.MenuItem
$ContextExit.Text = "Exit"
 
# Add the selections as context menus to the system tray icon
$ContextMenu = New-Object System.Windows.Forms.ContextMenu
$SysTray.ContextMenu = $ContextMenu
$SysTray.ContextMenu.MenuItems.AddRange($ContextOpen)
$SysTray.ContextMenu.MenuItems.AddRange($ContextSupport)
$SysTray.ContextMenu.MenuItems.AddRange($ContextExit)

# Action for left clicking on the icon in the system tray
$SysTray.Add_Click({     
    If ($_.Button -eq [Windows.Forms.MouseButtons]::Left) {
        # Start Flamingo
        Start-Process -WindowStyle hidden -FilePath "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy bypass -File `"$PSScriptRoot\Flamingo.ps1`"" -PassThru
    }
})

# Action for clicking on the Open selection
$ContextOpen.Add_Click({ 
    # Start Flamingo
    Start-Process -WindowStyle hidden -FilePath "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy bypass -File `"$PSScriptRoot\Flamingo.ps1`"" -PassThru
})

# Action for clicking on the Support selection
$ContextSupport.Add_Click({
    Start-Process -FilePath $ToolTicketUrl
})

# Action after clicking on the Exit context menu
$ContextExit.Add_Click({
    $SysTray.Visible = $false
    $window.Close()
    $AppContext.ExitThread()
    Stop-Process $Pid
})

# Make PowerShell Disappear
$Windowcode = '[DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);'
$ASyncWindow = Add-Type -MemberDefinition $WindowCode -Name Win32ShowWindowAsync -Namespace Win32Functions -PassThru
$null = $ASyncWindow::ShowWindowAsync((Get-Process -PID $Pid).MainWindowHandle, 0)

# Use a Garbage colection to reduce Memory use
[System.GC]::Collect()

# Create an application context for it to all run within - this helps with responsiveness, especially when clicking Exit
$AppContext = New-Object System.Windows.Forms.ApplicationContext
[void][System.Windows.Forms.Application]::Run($AppContext)