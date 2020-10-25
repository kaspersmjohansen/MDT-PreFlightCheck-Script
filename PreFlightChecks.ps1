# Configure variables for 
$LogDir = "$env:windir\Temp\MDT"
$LogPS = $LogDir + "\PreFlightChecks.log"
If (!(Test-Path -Path $LogPS))
{
New-Item -Path $LogDir -ItemType Directory
}

# Clear screen
Clear-Host

# Get operating system
$OS = (Get-WmiObject Win32_OperatingSystem).Caption

# Get machine domain membership
$ComputerDomain = (Get-WmiObject Win32_ComputerSystem).Domain

# Start transcript
Start-Transcript -Path $LogPS

# Bring any offline disks online
Get-Disk | where {$_.OperationalStatus -eq "Offline"} -Verbose | Set-Disk -IsOffline $false -Verbose | Set-Disk -IsReadOnly $false -Verbose

# Configure SAN policy to OnlineAll to prevent offline cache disks in the future
$GetSANPolicy = Get-StorageSetting | select NewDiskPolicy -ExpandProperty NewDiskPolicy
If ((!($GetSANPolicy -eq "OnlineAll")))
{
Write-Host $GetSANPolicy -Verbose
Write-host "Configuring new SAN policy" -Verbose
Set-StorageSetting –NewDiskPolicy OnlineAll
}

# Citrix PVS Cache Disk Remove Drive Letter
$CacheDisk = Get-Volume | where {$_.DriveLetter -ne "C" -and $_.DriveLetter -ne $null -and $_.DriveType -ne "CD-ROM"}
$CacheDiskDriveLetter = $CacheDisk.DriveLetter
Get-Volume -DriveLetter $CacheDiskDriveLetter  | Get-Partition | Remove-PartitionAccessPath -accesspath "$CacheDiskDriveLetter`:" -Verbose

# Configure optical drive driveletter to E:
$OpticalDisk = Get-WmiObject win32_volume -Filter 'DriveType="5"'
$OpticalDisk.DriveLetter = "E:"
$OpticalDisk.Put()

# Configure PVS cache disk driveletter to D:
Get-Volume -FileSystemLabel $CacheDisk.FileSystemLabel | Get-Partition | Set-Partition -NewDriveLetter D -Verbose

# Disable Server Manager startup at logon
If ($OS -like "*Windows Server*")
{
Set-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\ServerManager" -Name "DoNotOpenServerManagerAtLogon" -Value "1" -Verbose
}

If ($OS -like "*Windows Server 2019*")
{
Set-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\ServerManager" -Name "DoNotPopWACConsoleAtSMLaunch" -Value "1" -Verbose
}

# Add domain to Local Intranet Zone to prevent issues with Soft2Go package install
New-Item -Path "HKCU:Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\" -Name $ComputerDomain -Verbose
New-Item -Path "HKCU:Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\" -Name $ComputerDomain -Verbose
New-ItemProperty "HKCU:Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$ComputerDomain" -Name "*" -Value "1" -Type DWORD -Verbose
New-ItemProperty "HKCU:Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\$ComputerDomain" -Name "*" -Value "1" -Type DWORD -Verbose

# Start Windows Search service
$ServiceName = "WSearch"
$Service = Get-Service -Name $ServiceName
If (($Service).StartType -eq "Disabled")
{
    Set-Service -Name $ServiceName -StartupType Automatic -Verbose

        If (($Service).Status -eq "Stopped")
        {
            Start-Service -Name $ServiceName -Verbose
        
            # Disable Delayed Auto Start
            Set-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Services\WSearch" -Name "DelayedAutoStart" -Value "0" -Verbose
        }
}

Stop-Transcript