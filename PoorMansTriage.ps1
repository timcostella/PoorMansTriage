### Poor Man's Triage
### Version: 0.5.8
### Created: 08/04/2022
### Create By: Tim Costella
### Last Revised: 08/09/2022

## Check if running as an admin, alot of the functionality requrires running as admin
#Requires -RunASAdministrator

Function Convert-EnvVar
{

    [CmdletBinding()]
    param(
  
    [Parameter()]   
        [string]$Commandline
    )

    ## A lot of commandlines are parsed, some contain env variables such as %windir% or %systemroot% and they need to be converted to real paths

    #Count how many times we see % in the commandline, hopefully there will be 2
    $CountOfPercentChar = ($Commandline.ToCharArray() | Where-Object {$_ -eq "%"} | Measure-Object).count
            
    #If there are two % symbols we are going to assume it is a env var and try and convert
    if ($CountOfPercentChar -eq 2)
        {
            # I know there must be a better way...but here we go....
            $FirstCharPos = $Commandline.IndexOf("%") + 1
            $LastCharPos = $Commandline.LastIndexOf("%") -1
            $EnvVar = $Commandline.Substring($FirstCharPos,$LastCharPos)
            
            #Get the path for the env: variable 
            $PathForEnvVar = Get-ChildItem Env:\ | Where-Object { $_.name -eq $EnvVar } | Select-Object -ExpandProperty Value
            
            #Recreate the commandline
            if ($FirstCharPos -eq 1)
                {
                    $NewCommandLine =  $PathForEnvVar + $Commandline.Substring($LastCharPos+2)
                }
            else
                {
                    ## Why is it not at the beginning....something is goofed
                }
            
        }
        
        Write-Output $NewCommandLine
}

Function Get-NormalizedExe
{
    [CmdletBinding()]
    param(
  
    [Parameter()]   
        [string]$Commandline
    )

    #Used to convert commandlines from registry, processes, scheduled tasks, services, etc. to a simple path that can be hashed checked for a signature etc.
    # Example: "C:\Program Files\Common\MyApplication.exe" -a "C:\test\file.log" becomes C:\Program Files\Common\MyApplication.exe

    #Check if commandline contains environmental variables like %windir% 
    #Ex: %windir%\Executable.exe

    if ($Commandline.Contains("%"))
        {
            $CommandLine = Convert-EnvVar -Commandline $Commandline
        }
   
    if ($CommandLine.Contains("`""))
        {
            #Count how many times we see quotes in the commandline, hopefully there will be 2
            $CountOfQuotesChar = ($Commandline.ToCharArray() | Where-Object {$_ -eq "`""} | Measure-Object).count

            # If there are two quotes, we check to see if the first one is at the beginning of the string
            if ($CountOfQuotesChar -eq 2)
                {
                    #If the first quote is at the beginning of the line we assume the commandline is...
                    # "CommandLine" -arguments 
                    if($CommandLine.IndexOf("`"") -eq 0)
                        {
                            $FirstCharPos = 1
                            $LastCharPos = $Commandline.LastIndexOf("`"") - 1
                            
                            $CommandLine = $Commandline.Substring($FirstCharPos,$LastCharPos)
                        } 
                }
            else 
                {
                  # There are more than 2 quotes, so it could be "commandline" -arg "c:\argpath\args.dll"
                  # Alternatively it could be double quoting ""commandline""
                   
                  #Check for double quoting, lets hope it isn't ""commandline"" -args ""args""
                  if($Commandline.IndexOf("`"`"") -eq 0)
                        {
                            $FirstCharPos = 2
                            $LastCharPos = $Commandline.LastIndexOf("`"") - 2

                            $CommandLine = $Commandline.Substring($FirstCharPos,$LastCharPos)
                        }
                    else 
                        {
                            #Lets get the location of the second quote character, and assume the command line is everything proceeding the second quote character
                            $CommandLineAsArray = $Commandline.ToCharArray()
                            $Position = 0
                            $QuoteCount = 0

                            Foreach($Char in $CommandLineAsArray)
                                {
                                    if ($Char -eq "`"")
                                        {
                                            $QuoteCount = $QuoteCount + 1

                                            if($QuoteCount -eq 2)
                                                {
                                                    $EndOfCommandline = $Position -1 
                                                }
                                        }

                                    $Position++
                                }

                            $Commandline = $Commandline.Substring(1,$EndOfCommandline)
                        }

                }
        }
    else 
        {
            # No quotes in the commandline, so lets see how many spaces there are
            $CountOfSpaceChar = ($Commandline.ToCharArray() | Where-Object {$_ -eq " "} | Measure-Object).count

            if ($CountOfSpaceChar -eq 0)
                {
                    $Commandline = $Commandline
                }
            else 
                {
                    # Check for a .exe
                    $CommandlineLowerCase = $Commandline.ToLower()
                    $LastCharPos = $CommandlineLowerCase.IndexOf(".exe") + 4
                    if ($LastCharPos -gt 0)
                        {
                            $Commandline = $Commandline.Substring(0,$LastCharPos)
                        }
                    
                }
            
        }

    Write-Output $CommandLine
}

Function Get-HashesOfExes
{
    #Recive a bunch of commandlines as an array
    #Normalize the commandlines (i.e. remove arguments, env variables etc.) 
    #Generate a hash of the commandline executables
    #Save the hashes to a specified .csv.

    [CmdletBinding()]
    param(
    
        [Parameter()]   
        [string[]]$ExecutablesToHash,

        [Parameter()]   
        [string]$HashOutputFilePath
        
        
    )

    $Hashes=@()
    $NormalizedExes=@()

    Foreach ($Executable in $ExecutablesToHash)
        {
            Write-Verbose "Executable: $Executable"
            $NormalizedExe = Get-NormalizedExe -Commandline $Executable
            Write-Verbose "Normalized Executable: $NormalizedExe"
            $NormalizedExes += $NormalizedExe      
        }

    $NormalizedExes = $NormalizedExes | Sort-Object -Unique
    
    $Global:AllExes += $NormalizedExes
    
    Foreach ($Exe in $NormalizedExes)
        {
            $ExeCharCount = ($Exe.ToCharArray() | Measure-Object).Count

            if($ExeCharCount -gt 4)
                {
                    if(Test-Path -Path $Exe)
                        {
                            $Hash = Get-FileHash -Path $Exe -Algorithm MD5
                            $Hashes += $Hash
                            $HashValue = $Hash | Select-Object -ExpandProperty Hash

                            #Write a copy of each file hashed to a central file for checking against an online resource
                            "$Exe -  $HashValue" | Out-File -FilePath $AllHashesPath -Append
                            "$Exe - $HashValue" | Tee-Object -FilePath $Global:OutputFile -Append
                        }
                }
        }

    #Save all the hashes to the specified filename
    $Hashes | Export-Csv -Path $HashOutputFilePath

}


## Directory to save our work
$WorkingDirectory  = "C:\PoorMansTriageOutput" 
 
##Check if working directory exists, if not create it
if(-not (Test-Path -Path $WorkingDirectory))
    {
        New-Item -ItemType Directory -Path $WorkingDirectory -Force
    }

## the date and time that will be put in the output file names
$FileNameDate =  Get-Date -Format "MM_dd_yy_hh_mm"

## System Info
$SysInfo = Get-CimInstance -Class win32_computersystem

## Bios Info
$BiosInfo = Get-CimInstance -Class Win32_BIOS

## OperatingSystem Info
$OS = Get-CimInstance  -Class Win32_OperatingSystem

## CPU Info
$CPUs = Get-CimInstance Win32_Processor

## OS Patch Info
$Hotfixes = Get-Hotfix
$LastHotfixInstalled =  $Hotfixes | Sort-Object -Property InstalledOn -Descending | Select-Object -First 1 -ExpandProperty InstalledOn

## The domain the system is joined to
$DNSDomain =  $SysInfo.Domain

## Where to save the primary output file
$OutputFile = "$WorkingDirectory\$env:ComputerName-$DNSDomain-$FileNameDate-Triage.log"

## Where to save the complete network interface info
$OutputFile_NICs = "$WorkingDirectory\$env:ComputerName-$DNSDomain-$FileNameDate-Triage-NICs.csv"

## Where to save the dns info
$OutputFile_DNS = "$WorkingDirectory\$env:ComputerName-$DNSDomain-$FileNameDate-Triage-DNS.csv"

## Where to save the local user info
$OutputFile_LocalUsers = "$WorkingDirectory\$env:ComputerName-$DNSDomain-$FileNameDate-Triage-LocalUsers.csv"

## Where to save the local group info
$OutputFile_LocalGroups = "$WorkingDirectory\$env:ComputerName-$DNSDomain-$FileNameDate-Triage-LocalGroups.csv"

## where to save the list of processes
$ProcessPath = "$WorkingDirectory\$env:ComputerName-$DNSDomain-$FileNameDate-Triage-Processes.csv"

## where to save the process hashes
$ProcessHashesPath = "$WorkingDirectory\$env:ComputerName-$DNSDomain-$FileNameDate-Triage-ProcessHashes.csv"

## where to save the startup commands
$StartupCmdsPath = "$WorkingDirectory\$env:ComputerName-$DNSDomain-$FileNameDate-Triage-StartupCmd.csv"

## where to save the startup command hashes 
 $StartupCmdHashesPath = "$WorkingDirectory\$env:ComputerName-$DNSDomain-$FileNameDate-Triage-StartupCmdHashes.csv"

## Where to save the services
 $ServicesPath = "$WorkingDirectory\$env:ComputerName-$DNSDomain-$FileNameDate-Triage-Services.csv"

## where to save the services hashes 
 $ServicesHashesPath = "$WorkingDirectory\$env:ComputerName-$DNSDomain-$FileNameDate-Triage-ServiceHashes.csv"

## where to save the scheduled tasks (names, description, etc)
 $ScheduledTasksPath = "$WorkingDirectory\$env:ComputerName-$DNSDomain-$FileNameDate-Triage-ScheduledTasks.csv"

 ## where to save the scheduled tasks actions (what commands the scheduled tasks run)
 $ScheduledTasksActionsPaths = "$WorkingDirectory\$env:ComputerName-$DNSDomain-$FileNameDate-Triage-ScheduledTasksActions.csv"

## where to save the scheduled task action hashes
 $ScheduledTaskHashesPath = "$WorkingDirectory\$env:ComputerName-$DNSDomain-$FileNameDate-Triage-ScheduledTaskHashes.csv"

## Where to save a list of all "critical" executables (startupcmds, services, processes, scheduledtasks)
 $AllExesPath = "$WorkingDirectory\$env:ComputerName-$DNSDomain-$FileNameDate-Triage-AllExecutables.txt"

## Where to save the hashes of all the "critical" executables (startupcmds, services, processes, scheduledtasks)
 $AllHashesPath = "$WorkingDirectory\$env:ComputerName-$DNSDomain-$FileNameDate-Triage-AllHashes.txt"

 ## where to save the list of unsigned exes (executables with a signature that can't be validated or found)
 $UnsignedExesPath = "$WorkingDirectory\$env:ComputerName-$DNSDomain-$FileNameDate-Triage-UnsignedExes.csv"
 
## where to save the gresults (group policy results) 
$GPResultsPath = "$WorkingDirectory\$env:ComputerName-$DNSDomain-$FileNameDate-Triage-GPResults.html"

## where to save the compressed event logs
$ZippedEventLogsPath = "$WorkingDirectory\$env:ComputerName-$DNSDomain-$FileNameDate-Triage-EventLogs.zip"

## where to save the all the .txt and .csv zipped up logs (everything but event logs, because they are so big)
$ZippedOutputPath = "$WorkingDirectory\$env:ComputerName-$DNSDomain-$FileNameDate-Triage-AllLogs.zip"


### Get the timezone info
$TimeZone =  Get-TimeZone | Select-Object -ExpandProperty ID

### Script Information (Script Name, Who Ran It)
"SCRIPT INFO:******************************"  | Tee-Object -FilePath $OutputFile -Append
"SCRIPT: $PSCommandPath"  | Tee-Object -FilePath $OutputFile -Append
"SCRIPT RUN BY (UserDomain\UserName): $($env:UserDomain)\$($env:UserName)" | Tee-Object -FilePath $OutputFile -Append
$FileDate = Get-Date -Format "MM/dd/yy hh:mm:ss tt"
"SCRIPT RUN DATE/TIME: $FileDate $TimeZone"    | Tee-Object -FilePath $OutputFile -Append

### Show whether run by admin or not
$UserObj = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
if ($UserObj.IsInRole([Security.Principal.WindowsBuiltInRole]::"Administrator"))
    {
        "SCRIPT RUNNING AS ADMIN: YES" | Tee-Object -FilePath $OutputFile -Append
    }
else 
    {
        "SCRIPT RUNNING AS ADMIN: NO" | Tee-Object -FilePath $OutputFile -Append
    }


### Get system info
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"SYSTEM INFO: ******************************"  | Tee-Object -FilePath $OutputFile -Append
"SYSTEM: $env:ComputerName.$DNSDomain" | Tee-Object -FilePath $OutputFile -Append
"MANUFACTURER AND MODEL: $($SysInfo.Manufacturer) - $($SysInfo.Model)" | Tee-Object -FilePath $OutputFile -Append
"PROCESSOR MANUFACTURER AND MODEL: $($CPUs.Manufacturer) - $($CPUs.Name)" | Tee-Object -FilePath $OutputFile -Append
"SYSTEM OWNER: $($SysInfo.PrimaryOwnerName)" | Tee-Object -FilePath $OutputFile -Append
$TotalMemoryGB = [Math]::Round($SysInfo.TotalPhysicalMemory/1GB)
"TOTAL MEMORY GBs: $TotalMemoryGB" | Tee-Object -FilePath $OutputFile -Append
"TOTAL PROCESSORS: $($SysInfo.NumberOfProcessors) OR $($CPUs.NumberOfCores)" | Tee-Object -FilePath $OutputFile -Append
"TOTAL LOGICAL PROCESSORS: $($SysInfo.NumberOfLogicalProcessors) OR $($CPUs.NumberOfLogicalProcessors)" | Tee-Object -FilePath $OutputFile -Append
"BIOS SERIAL NUMBER: $($BiosInfo.SerialNumber)" | Tee-Object -FilePath $OutputFile -Append
"OS NAME: $($OS.Caption)" | Tee-Object -FilePath $OutputFile -Append
"OS VERSION: $($OS.Version)" | Tee-Object -FilePath $OutputFile -Append
"OS ARCHITECTURE: $($OS.OSArchitecture)" | Tee-Object -FilePath $OutputFile -Append
"OS LAST BOOT TIME: $($OS.LastBootUpTime)" | Tee-Object -FilePath $OutputFile -Append
"OS LAST PATCH INSTALLED: $LastHotfixInstalled" | Tee-Object -FilePath $OutputFile -Append


### Get Mounted Devices
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"MOUNTED DEVICES: *******************************"  | Tee-Object -FilePath $OutputFile -Append
Get-Item -Path "HKLM:\SYSTEM\MountedDevices\" | Select-Object -ExpandProperty Property | Sort-Object -Property Property | Tee-Object -FilePath $OutputFile -Append

### USB Devices that have been connected
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"USB DEVICES FROM REGISTRY: *********************"  | Tee-Object -FilePath $OutputFile -Append
Get-ChildItem -Path "HKLM:\SYSTEM\ControlSet001\Enum\USBSTOR\" | Get-ChildItem | Get-ItemProperty -Name FriendlyName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FriendlyName  | Sort-Object -Property FriendlyName | Tee-Object -FilePath $OutputFile -Append
Start-Process -FilePath "C:\windows\System32\reg.exe" -ArgumentList "export HKLM\SYSTEM\ControlSet001\Enum\USBSTOR $WorkingDirectory\HKLM_USBSTOR.reg /y"

### Get Disk Info
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"DISK INFO: *************************************"  | Tee-Object -FilePath $OutputFile -Append
$Disks = Get-Disk 
$Disks | Select-Object -Property Manufacturer, Model, SerialNumber, Size, PhysicalSectorSize, PartitionStyle, NumberOfPartitions, OperationalStatus  | Tee-Object -FilePath $OutputFile -Append

### Get Logical Disk Info
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"LOGICAL DISK INFO: *****************************"  | Tee-Object -FilePath $OutputFile -Append
$DisksObjs = Get-CimInstance -ClassName Win32_LogicalDisk
$DisksObjs | Select-Object -Property Name, VolumeName, VolumeSerialNumber, Size, FreeSpace, FileSystem, DriveType | Format-Table | Tee-Object -FilePath $OutputFile -Append

### Get Partition Info
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"DISK PARTITION INFO: *****************************"  | Tee-Object -FilePath $OutputFile -Append
$Partitions = Get-Partition
$Partitions | Select-Object -Property DiskNumber, PartitionNumber, Size, Type, DriveLetter, IsBoot, IsSystem, IsHidden | Sort-Object -Property DiskNumber, PartitionNumber | Format-Table | Tee-Object -FilePath $OutputFile -Append

### Get system proxy info
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"SYSTEM PROXY: *****************************"  | Tee-Object -FilePath $OutputFile -Append
netsh winhttp show proxy | Tee-Object -FilePath $OutputFile -Append

### Get nic info
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"NETWORK INFO: *****************************"  | Tee-Object -FilePath $OutputFile -Append
Get-NetIPAddress | Select-Object -Property IPAddress, InterfaceAlias | Sort-Object -Property InterfaceAlias | Tee-Object -FilePath $OutputFile -Append
Get-NetIPAddress | Export-Csv -Path $OutputFile_NICs

### Get host file content
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"HOST FILE CONTENT: ************************" | Tee-Object -FilePath $OutputFile -Append
Get-Content "C:\Windows\system32\drivers\etc\hosts" | Tee-Object -FilePath $OutputFile -Append

### Get DNS Information
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"DNS SERVERS: ******************************" | Tee-Object -FilePath $OutputFile -Append
Get-DnsClientServerAddress  | Select-Object -Property InterfaceAlias, InterfaceIndex, AddressFamily, ServerAddresses | Sort-Object -Property InterfaceAlias, AddressFamily | Tee-Object -FilePath $OutputFile -Append
Get-DnsClientServerAddress  | Select-Object -Property * | Sort-Object -Property InterfaceAlias, AddressFamily | Export-Csv -Path $OutputFile_DNS

### Get ARP Cache
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"ARP CACHE: *******************************" | Tee-Object -FilePath $OutputFile -Append
Get-NetNeighbor | Sort-Object -Property ifIndex, IpAddress, LinkLayerAddress | Format-Table | Tee-Object -FilePath $OutputFile -Append

### Get Routing Table
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"NETWORK ROUTES: ***************************" | Tee-Object -FilePath $OutputFile -Append
Get-NetRoute | Sort-Object DestinationPrefix | Tee-Object -FilePath $OutputFile -Append

### Get Wireless Networks From Registry
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"WIRELESS NETWORKS: ***************************" | Tee-Object -FilePath $OutputFile -Append
Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles" | Get-ItemProperty -Name ProfileName, Description, DateLastConnected | Select-Object ProfileName, Description, DateLastConnected | Tee-Object -FilePath $OutputFile -Append
Start-Process -FilePath "C:\windows\System32\reg.exe" -ArgumentList "export HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles $WorkingDirectory\HKLM_NetworkList_Profiles.reg /y"
### Get Network Connections

### Get local users
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"LOCAL USERS: ******************************" | Tee-Object -FilePath $OutputFile -Append
Get-LocalUser | Select-Object -Property Name, SID, Enabled, LastLogon, PasswordLastSet | Sort-Object -Property Name | Format-Table | Tee-Object -FilePath $OutputFile -Append
Get-LocalUser | Select-Object -Property * | Sort-Object -Property Name | Export-Csv -Path $OutputFile_LocalUsers

### Get local groups
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"LOCAL GROUPS: ******************************" | Tee-Object -FilePath $OutputFile -Append
$LocalGroups = Get-LocalGroup | Sort-Object -Property Name 
$LocalGroups | Select-Object -Property Name, SID | Sort-Object -Property Name | Tee-Object -FilePath $OutputFile -Append
$LocalGroups | Select-Object -Property * | Sort-Object -Property Name | Export-Csv -Path $OutputFile_LocalGroups

### Get local group members
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"LOCAL GROUP MEMBERS: ***********************" | Tee-Object -FilePath $OutputFile -Append
Foreach ($LocalGroup in $LocalGroups)
    {
        "Group: $LocalGroup" | Tee-Object -FilePath $OutputFile -Append
        $GroupMembers = Get-LocalGroupMember -Group $LocalGroup | Select-Object -ExpandProperty Name

          if ($GroupMembers)
            {

                Foreach ($GroupMember in $GroupMembers)
                    {
                        "    - Member: $GroupMember" | Tee-Object -FilePath $OutputFile -Append
                    }
            }
        else 
            {
                "    - No Members" | Tee-Object -FilePath $OutputFile -Append
            }
        
        # "`n`n" | Tee-Object -FilePath $OutputFile -Append
        
    }


### Get local profile folders
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"LOCAL PROFILE FOLDERS: ****************************" | Tee-Object -FilePath $OutputFile -Append
$UserProfiles = Get-CimInstance -ClassName Win32_UserProfile
$UserProfiles | Select-Object -Property SID, LocalPath, LastUseTime | Format-Table | Tee-Object -FilePath $OutputFile -Append


### Get local profiles in registry
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"LOCAL PROFILES IN REGISTRY: ***********************" | Tee-Object -FilePath $OutputFile -Append
Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" | Select-Object -ExpandProperty PSChildName | Tee-Object -FilePath $OutputFile -Append


### Get patch (hotfix) info
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"OS PATCHES: ******************************" | Tee-Object -FilePath $OutputFile -Append
$Hotfixes | Sort-Object -Property InstalledOn -Descending | Select-Object -Property HotfixID, Description, Caption, InstalledOn | Tee-Object -FilePath $OutputFile -Append

### Get last 20 setup events
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"LAST 20 Setup Log Events: ****************" | Tee-Object -FilePath $OutputFile -Append
Get-WinEvent -LogName Setup -MaxEvents 20 | Select-Object -Property TimeCreated, Message | Format-List | Tee-Object -FilePath $OutputFile -Append

## Get Installed Software
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"INSTALLED SOFTWARE:**********************" | Tee-Object -FilePath $OutputFile -Append
"PATH: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" | Tee-Object -FilePath $OutputFile -Append
$Software = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" | Get-ItemProperty -Name DisplayName, DisplayVersion -ErrorAction SilentlyContinue | Select-Object -Property DisplayName, DisplayVersion | Sort-Object -Property DisplayName
$Software | Tee-Object -FilePath $OutputFile -Append
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"PATH: HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" | Tee-Object -FilePath $OutputFile -Append
$Software = Get-ChildItem -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" | Get-ItemProperty -Name DisplayName, DisplayVersion -ErrorAction SilentlyContinue | Select-Object -Property DisplayName, DisplayVersion | Sort-Object -Property DisplayName
$Software | Tee-Object -FilePath $OutputFile -Append
 
### Get environment variables
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"OS ENVIRONMENTAL VARIABLES: **************" | Tee-Object -FilePath $OutputFile -Append
Get-ChildItem -Path Env:\ | Select-Object -Property Name, Value | Sort-Object -Property Name  | Tee-Object -FilePath $OutputFile -Append

## Need to add envornment variables for the system and each user, but that is a bit more work, so will add in a later version

### Get logged on users
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"LOGGED IN USERS: *************************" | Tee-Object -FilePath $OutputFile -Append
C:\windows\System32\qwinsta.exe | Tee-Object -FilePath $OutputFile -Append


### Get SMB shares
$Shares = Get-SmbShare
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"SMB SHARES: ******************************" | Tee-Object -FilePath $OutputFile -Append
$Shares | Tee-Object -FilePath $OutputFile -Append

### Get SMB shares access
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"SMB SHARE PERMS: *************************" | Tee-Object -FilePath $OutputFile -Append
$Shares | Get-SmbShareAccess | Sort-Object -Property Name | Tee-Object -FilePath $OutputFile -Append

###Get HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\ Registry entries
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"REGISTRY KEY (HKLM RUN): *************************" | Tee-Object -FilePath $OutputFile -Append
$AllRegKeys=@()
$RegKeys = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" 
$RegKeys | Tee-Object -FilePath $OutputFile -Append
$AllRegKeys += $RegKeys
Start-Process -FilePath "C:\windows\System32\reg.exe" -ArgumentList "export HKLM\Software\Microsoft\Windows\CurrentVersion\Run $WorkingDirectory\HKLM_Run.reg /y"

###Get HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\ Registry entries
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"REGISTRY KEY (HKLM RUN ONCE): *********************" | Tee-Object -FilePath $OutputFile -Append
$RegKeys = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" 
$RegKeys | Tee-Object -FilePath $OutputFile -Append
$AllRegKeys += $RegKeys
Start-Process -FilePath "C:\windows\System32\reg.exe" -ArgumentList "export HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce $WorkingDirectory\HKLM_RunOnce.reg /y"

### Get HKU Registry entries
$InterestingRegKeys=@("SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "software\microsoft\Software\Microsoft\InternetExplorer\TypedURLs", "software\microsoft\windows\currentversion\explorer\typedpaths")

"`n`n" | Tee-Object -FilePath $OutputFile -Append
"USER REGISTRY KEY: ***********************" | Tee-Object -FilePath $OutputFile -Append

#Iterate over the user profiles and save out some interesting keys under HKU:\SID\
Foreach ($UserProfile in $UserProfiles)
    {
        if ($UserProfile.SID -notmatch 'S-1-5-(18|19|20).*')
        {
            #Convert SID in profile to username (Domain\UserName)
            $SIDObject = New-Object System.Security.Principal.SecurityIdentifier($UserProfile.SID)
            $UserName = $SIDObject.Translate([System.Security.Principal.NTAccount]).Value
            
            #Convert Domain\UserName into Username
            if($UserName.IndexOf("\") -gt 0)
                {
                    $ShortName = $UserName.Split("\")[1]
                }
            else 
                {
                    $ShortName = $UserName
                }
           
            #Load the User's registry key
            Start-Process -FilePath "C:\Windows\System32\reg.exe" -ArgumentList "load HKU\$($UserProfile.SID) $($UserProfile.LOCALPATH)\NTUSER.DAT" -Wait
            "Username: $UserName ($($UserProfile.SID))" | Tee-Object -FilePath $OutputFile -Append
            
            #Loop through all the interesting keys
            Foreach($InterestingRegKey in $InterestingRegKeys)
                {
                    "Registry Key: $InterestingRegKey" | Tee-Object -FilePath $OutputFile -Append

                    #Last get the last part of the registry key for use in the file name of the exported key
                    $ShortKeyNameStart = $InterestingRegKey.LastIndexOf("\") + 1
                    $ShortKeyName = $InterestingRegKey.Substring($ShortKeyNameStart)

                    $RegKeys = Get-ItemProperty -Path Registry::"HKEY_USERS\$($UserProfile.SID)\$InterestingRegKey" 
                    #Save the user registry key to log file
                    $RegKeys | Tee-Object -FilePath $OutputFile -Append
                    $AllRunRegKeys += $RegKeys
                    #Export out the registry key
                    Start-Process -FilePath "C:\windows\System32\reg.exe" -ArgumentList "export HKU\$($UserProfile.SID)\$InterestingRegKey $WorkingDirectory\$ShortName-$ShortKeyName.reg /y" -Wait
                }
            
        }
        
    }

### Get startup command items
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"STARTUP COMMANDS: ************************" | Tee-Object -FilePath $OutputFile -Append
$StartupCmds = Get-CimInstance -ClassName Win32_StartupCommand
$StartupCmds | Export-Csv -Path $StartupCmdsPath
$StartupCmds | Select-Object -Property Name, Command, Location | Tee-Object -FilePath $OutputFile -Append

### Get startup command hashes
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"STARTUP COMMANDS HASHES: ******************" | Tee-Object -FilePath $OutputFile -Append
$StartupCmdExes = $StartupCmds | Select-Object -ExpandProperty Command
Get-HashesOfExes -ExecutablesToHash $StartupCmdExes -Verbose -HashOutputFilePath $StartupCmdHashesPath

### Get all services
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"SERVICES: ******************************" | Tee-Object -FilePath $OutputFile -Append
$Services = Get-CimInstance -ClassName Win32_Service | Select-Object -Property Name,DisplayName, Started, StartMode, PathName
$Services | Export-Csv -Path $ServicesPath 
$Services | Format-Table | Tee-Object -FilePath $OutputFile -Append

### Get hashes for services
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"SERVICE HASHES: *****************" | Tee-Object -FilePath $OutputFile -Append
$ServiceExes = $Services | Select-Object -ExpandProperty PathName | Sort-Object -Property PathName
Get-HashesOfExes -ExecutablesToHash $ServiceExes -Verbose -HashOutputFilePath $ServicesHashesPath

### Get scheduled tasks descriptions
$ScheduledTasks = Get-ScheduledTask
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"SCHEDULED TASKS: ***********************" | Tee-Object -FilePath $OutputFile -Append
$ScheduledTasks | Export-Csv -Path $ScheduledTasksPath
$ScheduledTasks | Select-Object -Property TaskName, State, Description | Sort-Object -Property TaskName | Format-Table | Tee-Object -FilePath $OutputFile -Append

### Get scheduled tasks actions
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"SCHEDULED TASKS ACTIONS: ****************" | Tee-Object -FilePath $OutputFile -Append
$ScheduledTaskActions = $ScheduledTasks | Select-Object -ExpandProperty Actions | Select-Object -Property Execute, Arguments -Unique
$ScheduledTaskActions | Export-Csv -Path $ScheduledTasksActionsPaths
$ScheduledTaskActions | Tee-Object -FilePath $OutputFile -Append

### Get hashes for scheduled task actions
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"SCHEDULED TASKS HASHES: *****************" | Tee-Object -FilePath $OutputFile -Append
$ScheduledTaskActionExes = $ScheduledTaskActions | Select-Object -ExpandProperty Execute
Get-HashesOfExes -ExecutablesToHash $ScheduledTaskActionExes  -Verbose -HashOutputFilePath $ScheduledTaskHashesPath

### Get running processes
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"RUNNING PROCESSES: *********************" | Tee-Object -FilePath $OutputFile -Append
$Processes = Get-CimInstance -Query "Select * from win32_process"
$ProcessInfo = $Processes | Select-Object Name, ProcessId, @{Label="Owner";Expression={$_.GetOwner()}}, CommandLine 
$ProcessInfo | Export-Csv -Path $ProcessPath
$ProcessInfo | Format-Table | Tee-Object -FilePath $OutputFile -Append

### Get running process hashes
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"RUNNING PROCESSES HASHES:****************" | Tee-Object -FilePath $OutputFile -Append
$CommandLines = $Processes | Select-Object -ExpandProperty ExecutablePath -Unique | Sort-Object -Unique
Get-HashesOfExes -ExecutablesToHash $CommandLines -Verbose -HashOutputFilePath $ProcessHashesPath

### Save list of all (service, processes, scheduled tasks) executables hashes to a file in case we want to iterate over the file and send to Virus Total etc....
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"ALL IMPORTANT PROCESSES HASHES:****************" | Tee-Object -FilePath $OutputFile -Append
$AllExes | Out-File -FilePath $AllExesPath
if (Test-Path -Path $AllExesPath)
    {
        if((Get-content -Path $AllExesPath).length -gt 10)
            {
                "Wrote All Service/Process/Scheduled Task/Startup Exes To $AllExesPath" | Tee-Object -FilePath $OutputFile -Append
            }
    }


###Check if each process, scheduled task, service, startup command etc is signed
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"CHECK SIGNATURES ON EXEs: *********************" | Tee-Object -FilePath $OutputFile -Append
$SignedExes = @()
$UnsignedExes = @()

Foreach ($AExe in $AllExes)
    {
        if (Test-Path -Path $AExe -ErrorAction SilentlyContinue)
            {
                $Signature = Get-AuthenticodeSignature -FilePath $AExe

                if ($Signature.Status -eq "Valid") 
                    {
                        $SignedExes += Select-Object -ExpandProperty SignerCertificate | Select-Object -Property @{Name="File";Expression={"$AExe"}}, Subject, Issuer, Thumbprint
                    }
                else 
                    {
                        $UnsignedExes += $AExe
                        "Unsigned Exe or Invalid Signature: $AExe" | Tee-Object -FilePath $OutputFile -Append
                        
                        ##Write filepath, signature.status to unsigned exe .csv
                    }
            }
        else 
            {
              ##Any paths that fail??
              "Failed to test signature on: $AExe" | Tee-Object -FilePath $OutputFile -Append

            }
    }

$UnsignedExes | Export-Csv -Path $UnsignedExesPath

### Make sure eventlogs are enabled
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"EVENT LOG ENABLED: *********************" | Tee-Object -FilePath $OutputFile -Append
$LogNames = @("Security","Application","Setup","System")
Foreach ($LogName in $LogNames)
    {
        $LogObj = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $LogName

        "Windows Event Log: $LogName is enabled: $($LogObj.IsEnabled)" | Tee-Object -FilePath $OutputFile -Append 
    }


### Backup event logs
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"EVENT LOG BACKUP: *********************" | Tee-Object -FilePath $OutputFile -Append
$LogNames = @("Security", "Setup", "Application", "System", "Windows PowerShell", "Microsoft-Windows-Sysmon/Operational")
Foreach ($LogName in $LogNames)
    {
        $EventLog = Get-WMIObject -ClassName Win32_NTEventlogFile -Filter "LogFileName='$LogName'"
        if($EventLog)
            {
                $BackupDestinationPath = "$WorkingDirectory\$env:ComputerName-$DNSDomain-$FileNameDate-Triage-EventLog-$LogName-Backup.evtx"
                $BackupStatus = $EventLog.BackupEventLog($BackupDestinationPath)
                
                Write-Output "BackupStatus"
                Write-Output $BackupStatus
                
                $result = New-Object -TypeName ComponentModel.Win32Exception($BackupStatus)
                
                Write-Output "result"
                Write-Output $result

                if ($result)
                    {
                        "Backed Up $LogName log to $BackupDestinationPath" | Tee-Object -FilePath $OutputFile -Append
                    }
            }
    }

 
### Zip up event logs
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"ZIP UP EVENT LOGS (.EVTX): *********************" | Tee-Object -FilePath $OutputFile -Append
$CompressSettings = @{
    Path = "$WorkingDirectory\*.evtx"
    CompressionLevel = "Optimal"
    DestinationPath = $ZippedEventLogsPath
}

Compress-Archive @CompressSettings

if(Test-Path -Path $ZippedEventLogsPath )
    {
        "Zipped Up Event Logs (.EVTX) to $ZippedEventLogsPath" | Tee-Object -FilePath $OutputFile -Append
         Remove-Item -Path "$WorkingDirectory\*.evtx" -Force
    }



### Get Windows Firewall Status

### Get Antivirus enabled

### Get Antivirus Definition Date

### Get Antivirus version


### Get GPRESULTS
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"GATHER GPRESULTS: *********************" | Tee-Object -FilePath $OutputFile -Append
Start-Process -FilePath "C:\Windows\System32\gpresult.exe" -ArgumentList "/H $GPResultsPath" -Wait

If (Test-Path -Path $GPResultsPath)
    {
        "GPResults saved to $GPResultsPath" | Tee-Object -FilePath $OutputFile -Append
    }



### Zip up all the csv output
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"ZIP UP CSV FILES: *********************" | Tee-Object -FilePath $OutputFile -Append
$CompressSettings = @{
    Path = @("$WorkingDirectory\*.csv", "$WorkingDirectory\*.html", "$WorkingDirectory\*.txt", "$WorkingDirectory\*.reg")
    CompressionLevel = "Optimal"
    DestinationPath = $ZippedOutputPath
}

Compress-Archive @CompressSettings

if(Test-Path -Path $ZippedOutputPath)
    {
        "Zipped Up CSVs to $ZippedOutputPath" | Tee-Object -FilePath $OutputFile -Append
        Remove-Item -Path "$WorkingDirectory\*.csv" -Force
        Remove-Item -Path "$WorkingDirectory\*.html" -Force
        Remove-Item -Path "$WorkingDirectory\*.reg" -Force
    }



#Script complete
"`n`n" | Tee-Object -FilePath $OutputFile -Append
"SCRIPT COMPLETE:*************************"  | Tee-Object -FilePath $OutputFile -Append
$FileDate = Get-Date -Format "MM/dd/yy hh:mm:ss tt"
"COMPLETED AT: $FileDate $TimeZone"    | Tee-Object -FilePath $OutputFile -Append