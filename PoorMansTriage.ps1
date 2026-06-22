### Poor Man's Triage
### Version: 0.5.9
### Created: 08/04/2022
### Created By: Tim Costella
### Last Revised: 06/13/2026

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


Function Get-PowerShellHistory
{
    <#
    .SYNOPSIS
    Gets a copy of the specified user's PowerShell history 
    
    .DESCRIPTION  
    Gets a copy of the specified user's PowerShell history.  As there might be multiple versions of powershell installed, we will check the powershell history location using the automatic variable for this session, 
    as well as the powershell 5 and powershell 7 specific history locations.
    
    The PowerShell 5 history is located at %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
    The PowerShell 7 history is located at %APPDATA%\Microsoft\PowerShell\PSReadLine\ConsoleHost_history.txt

    .PARAMETER UserName
    Which user to grab the PowerShell history from, default is $env:Username (user running this script)

    .PARAMETER OutputFile
    Where to save a copy of the PowerShell history file, default is "$WorkingDirectory\$env:ComputerName-$DNSDomain-$FileNameDate-Triage-PowerShellHistory.txt"

    .EXAMPLE
    Get-PowerShellHistory
    #>

    [CmdletBinding()]
    [Alias("Get-PSHistory")]
	param(  
          [Parameter()]
            [string]$UserName = $env:UserName,
            [string]$OutputFile = "$WorkingDirectory\$env:ComputerName-$DNSDomain-$FileNameDate-Triage-PowerShellHistory-$env:UserName.txt"        
    )
  
    ## The PowerShell 5 history location
    $PowerShell5HistoryLocation = "C:\Users\$UserName\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"

    ## The PowerShell 7 history location
    $PowerShell7HistoryLocation = "C:\Users\$UserName\AppData\Roaming\Microsoft\PowerShell\PSReadLine\ConsoleHost_history.txt"

     $PowerShellHistoryThisSession = (Get-PSReadlineOption).HistorySavePath
     if ($PowerShellHistoryThisSession -ne $PowerShell5HistoryLocation -and $PowerShellHistoryThisSession -ne $PowerShell7HistoryLocation)
        {
            "`n`n"  | Tee-Object -FilePath $GlobalOutputFile -Append
            Get-Content -Path $PowerShellHistoryThisSession | Out-File -FilePath $OutputFile -Append
            "SAVED POWERSHELL HISTORY FOR $UserName TO $OutputFile" | Tee-Object -FilePath $GlobalOutputFile -Append
        }
 
    if (Test-Path -Path $PowerShell5HistoryLocation )
        {
            "`n`n"  | Tee-Object -FilePath $GlobalOutputFile -Append
            "POWERSHELL 5 HISTORY FOR $UserName" | Tee-Object -FilePath $OutputFile -Append
            $PowerShell5History = Get-Content "C:\Users\$UserName\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"   
            $PowerShell5History | Out-File -FilePath $OutputFile -Append 
        }

    ## The PowerShell 7 history
    if (Test-Path -Path $PowerShell7HistoryLocation)   
        {
            "`n`n"  | Out-File -FilePath $GlobalOutputFile -Append
            "POWERSHELL 7 HISTORY FOR $UserName" | Tee-Object -FilePath $OutputFile -Append
            $PowerShell7History = Get-Content "C:\Users\$UserName\AppData\Roaming\Microsoft\PowerShell\PSReadLine\ConsoleHost_history.txt"
            $PowerShell7History | Out-File -FilePath $OutputFile -Append      
        }
}

Function Get-DomainInfo
{
    ### Check if system is domained joined
try 
    {
            $DOMAIN = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            "SYSTEM JOINED TO DOMAIN: $DOMAIN" | Tee-Object -FilePath $GlobalOutputFile -Append
            $DomainJoined = $true
    }  
catch 
    {     
            if ($_ -like "*not associated with an Active Directory domain or forest*")  
                { 
                    "SYSTEM IS NOT JOINED TO A DOMAIN" | Tee-Object -FilePath $GlobalOutputFile -Append
                }  
    }

if ($DomainJoined)
    {
        ### Get Active Directory Domain Information
        "`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
        "ACTIVE DIRECTORY DOMAIN: ******************************"  | Tee-Object -FilePath $GlobalOutputFile -Append
        "LOGON SERVER: $($env:LOGONSERVER)" | Tee-Object -FilePath $GlobalOutputFile -Append
        $CurrentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        "FSMO ROLE HOLDER - PDC EMULATOR: $($CurrentDomain.PdcRoleOwner)" | Tee-Object -FilePath $GlobalOutputFile -Append
        "FSMO ROLE HOLDER - RID MASTER: $($CurrentDomain.RidRoleOwner)" | Tee-Object -FilePath $GlobalOutputFile -Append
        "FSMO ROLE HOLDER - INFRASTRUCTURE MASTER: $($CurrentDomain.InfrastructureRoleOwner)" |  Tee-Object -FilePath $GlobalOutputFile -Append
        "DOMAIN CONTROLLERS: $($CurrentDomain.DomainControllers)" | Tee-Object -FilePath $GlobalOutputFile -Append     
        "FOREST: $($CurrentDomain.Forest)" | Tee-Object -FilePath $GlobalOutputFile -Append

        ### Get Active Directory Password Policy
        "`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
        "ACTIVE DIRECTORY PASSWORD POLICY: ******************************"  | Tee-Object -FilePath $GlobalOutputFile -Append
        net accounts | Tee-Object -FilePath $GlobalOutputFile -Append
    }

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

### Get the timezone info
$TimeZone =  Get-TimeZone

## Where to save the primary output file
$GlobalOutputFile = "$WorkingDirectory\$env:ComputerName-$DNSDomain-$FileNameDate-Triage.log"

## Where to save the list of installed devices
$OutputFile_InstalledDevices = "$WorkingDirectory\$env:ComputerName-$DNSDomain-$FileNameDate-Triage-InstalledDevices.csv"

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

## where to save the powershel history 
$PowerShellHistoryPath = "$WorkingDirectory\$env:ComputerName-$DNSDomain-$FileNameDate-Triage-PowerShellHistory.txt"

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




### Script Information (Script Name, Who Ran It)
"SCRIPT INFO:******************************"  | Tee-Object -FilePath $GlobalOutputFile -Append
"SCRIPT: $PSCommandPath"  | Tee-Object -FilePath $GlobalOutputFile -Append
"SCRIPT RUN BY (UserDomain\UserName): $($env:UserDomain)\$($env:UserName)" | Tee-Object -FilePath $GlobalOutputFile -Append
$FileDate = Get-Date -Format "MM/dd/yy hh:mm:ss tt"
"SCRIPT RUN DATE/TIME: $FileDate $TimeZone"    | Tee-Object -FilePath $GlobalOutputFile -Append
"SCRIPT RUN IN: POWERSHELL $($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)" | Tee-Object -FilePath $GlobalOutputFile -Append



### Show whether run by admin or not
$UserObj = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
if ($UserObj.IsInRole([Security.Principal.WindowsBuiltInRole]::"Administrator"))
    {
        "SCRIPT RUNNING AS ADMIN: YES" | Tee-Object -FilePath $GlobalOutputFile -Append
    }
else 
    {
        "SCRIPT RUNNING AS ADMIN: NO" | Tee-Object -FilePath $GlobalOutputFile -Append
    }


### Get system info
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"SYSTEM INFO: ******************************"  | Tee-Object -FilePath $GlobalOutputFile -Append
"SYSTEM: $env:ComputerName.$DNSDomain" | Tee-Object -FilePath $GlobalOutputFile -Append
"MANUFACTURER AND MODEL: $($SysInfo.Manufacturer) - $($SysInfo.Model)" | Tee-Object -FilePath $GlobalOutputFile -Append
"PROCESSOR MANUFACTURER AND MODEL: $($CPUs.Manufacturer) - $($CPUs.Name)" | Tee-Object -FilePath $GlobalOutputFile -Append
"SYSTEM OWNER: $($SysInfo.PrimaryOwnerName)" | Tee-Object -FilePath $GlobalOutputFile -Append
"SYSTEM TIME: $FileDate" | Tee-Object -FilePath $GlobalOutputFile -Append
"SYSTEM TIMEZONE: $($TimeZone.StandardName) $($TimeZone.DisplayName)" | Tee-Object -FilePath $GlobalOutputFile -Append
$TotalMemoryGB = [Math]::Round($SysInfo.TotalPhysicalMemory/1GB)
"TOTAL MEMORY GBs: $TotalMemoryGB" | Tee-Object -FilePath $GlobalOutputFile -Append
"TOTAL PROCESSORS: $($SysInfo.NumberOfProcessors) OR $($CPUs.NumberOfCores)" | Tee-Object -FilePath $GlobalOutputFile -Append
"TOTAL LOGICAL PROCESSORS: $($SysInfo.NumberOfLogicalProcessors) OR $($CPUs.NumberOfLogicalProcessors)" | Tee-Object -FilePath $GlobalOutputFile -Append
"BIOS SERIAL NUMBER: $($BiosInfo.SerialNumber)" | Tee-Object -FilePath $GlobalOutputFile -Append
"OS NAME: $($OS.Caption)" | Tee-Object -FilePath $GlobalOutputFile -Append
"OS INSTALL DATE: $($OS.InstallDate)" | Tee-Object -FilePath $GlobalOutputFile -Append
"OS VERSION: $($OS.Version)" | Tee-Object -FilePath $GlobalOutputFile -Append
"OS ARCHITECTURE: $($OS.OSArchitecture)" | Tee-Object -FilePath $GlobalOutputFile -Append
"OS LAST BOOT TIME: $($OS.LastBootUpTime)" | Tee-Object -FilePath $GlobalOutputFile -Append
"OS UPTIME (DAYS): $((Get-Date) - ($OS.LastBootUpTime)).TotalDays" | Tee-Object -FilePath $GlobalOutputFile -Append
"OS LAST PATCH INSTALLED: $LastHotfixInstalled" | Tee-Object -FilePath $GlobalOutputFile -Append



### Get Clipboard Content
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"CLIPBOARD CONTENT: ******************************"  | Tee-Object -FilePath $GlobalOutputFile -Append
try 
    {
        $Clipboard_Contents = Get-Clipboard

        if ($Clipboard_Contents.Length -ne 0)
            {
                $Clipboard_Contents | Tee-Object -FilePath $GlobalOutputFile -Append
            }
        else 
            {
               "No content in the clipboard" | Tee-Object -FilePath $GlobalOutputFile -Append   
            }
        
    }
catch
    {
        "Unable to get clipboard content, likely because the script is running in a non-interactive session (e.g. as SYSTEM or via psexec) or there is no clipboard content." | Tee-Object -FilePath $GlobalOutputFile -Append
    }



### Get PowerShell History
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"GATHERING POWERSHELL HISTORY: ******************************"  | Out-File -FilePath $GlobalOutputFile -Append
Get-PowerShellHistory
"PowerShell History saved to file"  | Out-File -FilePath $GlobalOutputFile -Append


### Get Prefech Items
# The name of the prefetch file takes on the format: {executable_name}-{hash}.pf, where executable_name is the name of the executable file that was run, and hash provides a hash of the executable's path and the command line used to launch the executable. 
# If the same executable was run with different command line options, or the executable was moved and then run again, this essentially means there will be more than one prefetch entry for it.
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"WINDOWS PREFETCH ITEMS: ******************************"  | Out-File -FilePath $GlobalOutputFile -Append
$PrefechItems = Get-ChildItem C:\Windows\Prefetch | Sort-Object -Property LastWriteTime -Descending  
$PrefechItems | Out-File -FilePath $GlobalOutputFile -Append

### Get the AmCache 
# AmCache’s contribution to forensic investigations: The AmCache registry hive’s role in storing information about executed and installed applications is crucial, yet it’s often mistakenly believed to capture every execution event. 
# This misunderstanding can lead to significant gaps in forensic narratives, particularly where malware employs evasion techniques. 
# Moreover, the lack of execution timestamp specificity in AmCache data further complicates accurate timeline reconstruction.
# https://www.microsoft.com/en-us/security/blog/2024/04/23/new-microsoft-incident-response-guide-helps-simplify-cyberthreat-investigations/

# A Windows Registry hive that is created to store information related to installed applications, programs executed (or present), drivers loaded, and more
# Tracks application files, executed programs, driver binaries, PnP devices, driver packages, device containers, and application shortcuts from Windows 10+ systems
# Executable file name, file path, SHA1 hash, metadata and timestamps are recorded
# The SHA1 hash in AmCache is only calculated for the first 31,457,280 bytes (30 MB) of large files
# Stored in a separate file named Amcache.hve within %SYSTEMROOT%\appcompat\Program

# AmCache should be considered an “evidence of presence” or “evidence of existence” artifact – it cannot be used to prove a binary executed
# Use AmCache to show that a file exists (or previously existed) in a given location


###  Get Prefetch files
# Prefect is designed to speed up the subsequent launch of applications to improve the overall user experience
# Prefetch is located in %SYSTEMROOT%\Prefetch
# Prefetch is enabled by default on Windows desktop operating systems, but not on Windows Server
# The prefetching process typically operates within the first ~10 seconds of an application launch, and monitors the files and directories with which an application interacts
# We, as forensic investigators, can leverage Prefetch as a generally reliable evidence of execution artifact
# In Windows 8 and later, the last 8 times of execution are recorded, and the first time of execution can be derived based upon the creation time of the .pf file minus a ~0-10 second delta for the prefetching process
# In Windows 8 and later, 1,024 Prefetch files are kept, using a first in first out process
# The 8-character hash! The Prefetch hash shown in .pf filenames is computed based upon the file path of the executable and, in some cases, the command line parameters utilized
# For example, notice that you’ll see numerous svchost.exe Prefetch files due to the numerous –k flags utilized by svchost.exe
# Prefetch is NOT enabled by default on Windows Server operating systems
# In most cases, you can determine the first time and most recent 8 times of execution for a given binary using Prefetch
# The creation time (B) of a .pf file will generally indicate the first time that binary executed on the system (assuming previous Prefetch files were not removed)
# The last modification time (M) of a .pf file will generally indicate the last time that binary executed on the system
# A delta of 0-10 seconds will need to be subtracted from the creation and modification times to account for the prefetching process time, which varies by application
# Parsing a Prefetch file with a forensic tool can reveal a list of files and directories with which a binary has interacted




### Get Recent Items (.lnk files)
### Recent Items are shortcuts to recently accessed files, folders, and websites. They are stored in the Recent Items folder located at %APPDATA%\Microsoft\Windows\Recent.
# Link files (.lnk) are shortcut files created upon creation of the file with which they are associated;
# they are primarily used by Windows for the metadata contained within them
# Jump Lists are a collection of Link files
# Upon right-clicking an application
# Link files are located in: %USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent
# Link files can be used as evidence of files that may have once existed but have since been deleted from the device
# Link files contain the Modified, Accessed, and Creation times of the target file
# The creation time of a Link file indicates the first time the target file was created
# The modification time of a Link file indicates the last time the target file was opened
# Other key metadata within a Link file includes target file path, file size, file attributes, origin system name, and origin volume information

# Jump Lists are located in: 
#    %USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations
#    %USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations

# Jump Lists can be useful for seeing files with which a given application has interacted, as well as other relevant information
# Jump Lists contained within AutomaticDestinations pertain to Windows OS provided features common amongst multiple applications; \
# CustomDestinations contain application specific Jump Lists utilized by various applications for a specific purpose
# AutomaticDestinations are in CDF format






"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"RECENT ITEMS: ******************************"  | Tee-Object -FilePath $GlobalOutputFile -Append
$RecentItems = Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent" 
$RecentItems | Select-Object -Property BaseName, LastAccessTimeUtc -Unique  | Sort-Object -Property LastAccessTimeUtc | Format-Table -AutoSize | Tee-Object -FilePath $GlobalOutputFile -Append
$RecentItems | Export-csv -Path "$WorkingDirectory\$env:ComputerName-$DNSDomain-$FileNameDate-Triage-RecentItems.csv" -Delimiter "," -NoTypeInformation


### Check if logs are enabled
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"SYSTEM LOGS (SYSTEM, APPLICATION, SETUP, SECURITY) STATUS: *********************" | Tee-Object -FilePath $GlobalOutputFile -Append
$LogNames = @("Security","Application","Setup","System")
Foreach ($LogName in $LogNames)
    {
        $LogObj = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $LogName

            if ($LogObj.IsEnabled -eq $false)
                {
                    "WINDOWS SYSTEM LOG: $LogName IS NOT ENABLED" | Tee-Object -FilePath $GlobalOutputFile -Append
                }
            else 
                {
                    "WINDOWS SYSTEM LOG: $LogName IS ENABLED" | Tee-Object -FilePath $GlobalOutputFile -Append
                    
                    ## check the size of the log, if it is full etc
                }
    }


### Get Antivirus Status
### We can check the status of the built in Windows Defender Antivirus using the Get-MpComputerStatus cmdlet. 
### This will show us if antivirus is enabled, if real time protection is enabled, when the last antivirus signature update was, etc.
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"ANTIVIRUS STATUS: *********************" | Tee-Object -FilePath $GlobalOutputFile -Append
Get-MpComputerStatus | Select-Object -Property AntivirusEnabled, RealTimeProtectionEnabled, AMServiceEnabled, NISProtectionEnabled, AntivirusSignatureLastUpdated, AntivirusSignatureVersion | Tee-Object -FilePath $GlobalOutputFile -Append 


### Get Stored Credentials
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"CMDKEY: *******************************"  | Tee-Object -FilePath $GlobalOutputFile -Append
cmdkey /list | Tee-Object -FilePath $GlobalOutputFile -Append


### Get Kerberos Tickets
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"KERBEROS TICKETS: ******************************"  | Tee-Object -FilePath $GlobalOutputFile -Append
try 
    {
        klist tickets | Tee-Object -FilePath $GlobalOutputFile -Append
    }
catch
    {
        "Unable to get kerberos tickets, likely because the script is running in a non-interactive session (e.g. as SYSTEM or via psexec)." | Tee-Object -FilePath $GlobalOutputFile -Append
    }   

### Get installed devices
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"INSTALLED DEVICES: ******************************"  | Tee-Object -FilePath $GlobalOutputFile -Append
$InstalledDevices = Get-CimInstance Win32_PnPEntity 
$InstalledDevices | Select-Object Name, Manufacturer -Unique | Sort-Object -Property Name, Manufacturer | Format-Table -AutoSize | Tee-Object -FilePath $GlobalOutputFile -Append
$InstalledDevices | Select-Object -Property * | Sort-Object -Property Name, Manufacturer | Export-Csv -Path $OutputFile_InstalledDevices -Delimiter "," -NoTypeInformation

### Get Mounted Devices
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"MOUNTED DEVICES: *******************************"  | Tee-Object -FilePath $GlobalOutputFile -Append
Get-Item -Path "HKLM:\SYSTEM\MountedDevices\" | Select-Object -ExpandProperty Property | Sort-Object -Property Property | Tee-Object -FilePath $GlobalOutputFile -Append

### USB Devices that have been connected
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"USB DEVICES FROM REGISTRY: *********************"  | Tee-Object -FilePath $GlobalOutputFile -Append
Get-ChildItem -Path "HKLM:\SYSTEM\ControlSet001\Enum\USBSTOR\" | Get-ChildItem | Get-ItemProperty -Name FriendlyName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FriendlyName  | Sort-Object -Property FriendlyName | Tee-Object -FilePath $GlobalOutputFile -Append
Start-Process -FilePath "C:\windows\System32\reg.exe" -ArgumentList "export HKLM\SYSTEM\ControlSet001\Enum\USBSTOR $WorkingDirectory\HKLM_USBSTOR.reg /y"

### Get Disk Info
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"DISK INFO: *************************************"  | Tee-Object -FilePath $GlobalOutputFile -Append
$Disks = Get-Disk 
$Disks | Select-Object -Property Manufacturer, Model, SerialNumber, Size, @{Name="SizeGB";Expression={$_.Size/1Gb}}, PhysicalSectorSize, PartitionStyle, NumberOfPartitions, OperationalStatus  | Tee-Object -FilePath $GlobalOutputFile -Append

### Get Logical Disk Info
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"LOGICAL DISK INFO: *****************************"  | Tee-Object -FilePath $GlobalOutputFile -Append
$DisksObjs = Get-CimInstance -ClassName Win32_LogicalDisk
$DisksObjs | Select-Object -Property Name, VolumeName, VolumeSerialNumber, Size, @{Name="SizeGB";Expression={$_.Size/1Gb}}, FreeSpace, @{Name="FreeSpaceGB";Expression={$_.FreeSpace/1Gb}}, FileSystem, DriveType | Format-Table | Tee-Object -FilePath $GlobalOutputFile -Append

### Get Partition Info
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"DISK PARTITION INFO: *****************************"  | Tee-Object -FilePath $GlobalOutputFile -Append
$Partitions = Get-Partition
$Partitions | Select-Object -Property DiskNumber, PartitionNumber, Size,  @{Name="SizeGB";Expression={$_.Size/1Gb}}, Type, DriveLetter, IsBoot, IsSystem, IsHidden | Sort-Object -Property DiskNumber, PartitionNumber | Format-Table | Tee-Object -FilePath $GlobalOutputFile -Append

### Get system proxy info
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"SYSTEM PROXY: *****************************"  | Tee-Object -FilePath $GlobalOutputFile -Append
netsh winhttp show proxy | Tee-Object -FilePath $GlobalOutputFile -Append

### Get nic info
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"NETWORK INFO: *****************************"  | Tee-Object -FilePath $GlobalOutputFile -Append
Get-NetIPAddress | Select-Object -Property IPAddress, InterfaceAlias | Sort-Object -Property InterfaceAlias | Tee-Object -FilePath $GlobalOutputFile -Append
Get-NetIPAddress | Export-Csv -Path $OutputFile_NICs

### Get host file content
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"HOST FILE CONTENT: ************************" | Tee-Object -FilePath $GlobalOutputFile -Append
Get-Content "C:\Windows\system32\drivers\etc\hosts" | Tee-Object -FilePath $GlobalOutputFile -Append

### Get DNS Information
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"DNS SERVERS: ******************************" | Tee-Object -FilePath $GlobalOutputFile -Append
$ClientServerAddresses = Get-DnsClientServerAddress  
$ClientServerAddresses | Select-Object -Property InterfaceAlias, InterfaceIndex, AddressFamily, ServerAddresses | Sort-Object -Property InterfaceAlias, AddressFamily | Format-Table -AutoSize | Tee-Object -FilePath $GlobalOutputFile -Append
$ClientServerAddresses | Select-Object -Property * | Sort-Object -Property InterfaceAlias, AddressFamily | Export-Csv -Path $OutputFile_DNS

### Get DNS Client Cache
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"DNS CLIENT CACHE: ******************************" | Tee-Object -FilePath $GlobalOutputFile -Append
$DNSClientCache = Get-DnsClientCache 
$DNSClientCache | Select-Object -Property Name, Data -Unique | Sort-Object -Property Name | Format-Table -AutoSize | Tee-Object -FilePath $GlobalOutputFile -Append
$DNSClientCache | Select-Object -Property * | Export-CSV -Path $OutputFile_DNS_Cache -Delimiter "," -NoTypeInformation

### Get ARP Cache
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"ARP CACHE: *******************************" | Tee-Object -FilePath $GlobalOutputFile -Append
$ArpCache = Get-NetNeighbor 
$ArpCache | Select-Object -Unique | Sort-Object -Property IpAddress, LinkLayerAddress | Format-Table | Tee-Object -FilePath $GlobalOutputFile -Append

### Get Routing Table
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"NETWORK ROUTES: ***************************" | Tee-Object -FilePath $GlobalOutputFile -Append
Get-NetRoute | Sort-Object DestinationPrefix | Format-Table -AutoSize | Tee-Object -FilePath $GlobalOutputFile -Append

### Get Listening Ports
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"LISTENING PORTS: ***************************" | Tee-Object -FilePath $GlobalOutputFile -Append
$TCPConnections = Get-NetTCPConnection
$TCPConnections | Select-Object -Property LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess, State, @{Name="ProcessDescription";Expression={Get-Process -id $_.OwningProcess | Select-Object -ExpandProperty Description}},  @{Name="ProcessCommandLine";Expression={Get-Process -id $_.OwningProcess | Select-Object -ExpandProperty CommandLine}} | Format-List  | Tee-Object -FilePath $GlobalOutputFile -Append
$TCPConnections | Export-Csv -Path $OutputFile_ListeningPorts -Delimiter "," -NoTypeInformation
# $TCPConnections | Select-Object -Property LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess, State, @{Name="ProcessName";Expression={Get-Process -id $_.OwningProcess | Select-Object -ExpandProperty Path}}, @{Name="ProcessDescription";Expression={Get-Process -id $_.OwningProcess | Select-Object -ExpandProperty Description}},  @{Name="ProcessCommandLine";Expression={Get-Process -id $_.OwningProcess | Select-Object -ExpandProperty CommandLine}} | Format-List  | Tee-Object -FilePath $GlobalOutputFile -Append

### Get Listening Ports that have a remote address connected (i.e. not just listening locally)
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"PORTS LISTEN FOR REMOTE CONNECTIONS: ***************************" | Tee-Object -FilePath $GlobalOutputFile -Append
$TCPConnections | Where-Object {$_.RemoteAddress -ne "0.0.0.0" -and $_.RemoteAddress -ne "127.0.0.1"} | Select-Object -Property LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess, State, @{Name="ProcessName";Expression={Get-Process -id $_.OwningProcess | Select -ExpandProperty Path}}, @{Name="ProcessDescription";Expression={Get-Process -id $_.OwningProcess | Select -ExpandProperty Description}}, @{Name="ProcessCommandLine";Expression={Get-Process -id $_.OwningProcess | Select-Object -ExpandProperty CommandLine}} | Format-List | Tee-Object -FilePath $GlobalOutputFile -Append

"REMOTE IPS/PORTS CONNECTED TO: ***************************" | Tee-Object -FilePath $GlobalOutputFile -Append
$TCPConnections | Where-Object {$_.RemoteAddress -ne "0.0.0.0" -and $_.RemoteAddress -ne "127.0.0.1"} | Select-Object -Property RemoteAddress, RemotePort  -Unique  | Tee-Object -FilePath $GlobalOutputFile -Append

### Get Wireless Networks From Registry
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"WIRELESS NETWORKS: ***************************" | Tee-Object -FilePath $GlobalOutputFile -Append
Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles" | Get-ItemProperty -Name ProfileName, Description, DateLastConnected | Select-Object ProfileName, Description, DateLastConnected | Tee-Object -FilePath $GlobalOutputFile -Append
Start-Process -FilePath "C:\windows\System32\reg.exe" -ArgumentList "export HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles $WorkingDirectory\HKLM_NetworkList_Profiles.reg /y"

### Get Windows Firewall Service Status
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"WINDOWS FIREWALL SERVICE STATUS: ***************************" | Tee-Object -FilePath $GlobalOutputFile -Append
Get-Service -Name "MpsSvc" | Select-Object -Property Name, DisplayName, Status, StartType | Tee-Object -FilePath $GlobalOutputFile -Append

### Get Windows Firewall Status
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"WINDOWS FIREWALL STATUS: ***************************" | Tee-Object -FilePath $GlobalOutputFile -Append
Get-NetFirewallProfile | Select-Object -Property Name, Enabled, DefaultInboundAction, DefaultOutboundAction, AllowInboundRules, AllowOutboundRules | Tee-Object -FilePath $GlobalOutputFile -Append

### Get Windows Firewall Rules
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"WINDOWS FIREWALL RULES: ***************************" | Tee-Object -FilePath $GlobalOutputFile -Append
$FirewallRules = Get-NetFirewallRule 
$FirewallRules | Select-Object -Property Name, DisplayName, Enabled, Direction, Action, Profile, Grouping | Where-Object {$_.Enabled -eq $true} | Sort-Object -Property DisplayName | Format-Table -AutoSize | Tee-Object -FilePath $GlobalOutputFile -Append
$FirewallRules | Select-Object -Property * | Sort-Object -Property DisplayName | Export-Csv -Path "$WorkingDirectory\$env:ComputerName-$DNSDomain-$FileNameDate-Triage-FirewallRules.csv" -Delimiter "," -NoTypeInformation

### Get local users
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"LOCAL USERS: ******************************" | Tee-Object -FilePath $GlobalOutputFile -Append
$LocalUsers = Get-LocalUser 
$LocalUsers | Select-Object -Property Name, Description, SID, Enabled, LastLogon, PasswordLastSet | Sort-Object -Property Name | Format-List | Tee-Object -FilePath $GlobalOutputFile -Append
$LocalUsers | Select-Object -Property * | Sort-Object -Property Name | Export-Csv -Path $OutputFile_LocalUsers

### Check if local guest is enabled
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"CHECK LOCAL GUEST ACCOUNT: ******************************" | Tee-Object -FilePath $GlobalOutputFile -Append
$LocalGuest = $LocalUsers | Where-Object {$_.SID -like "*-501"}
if ($LocalGuest)
    {
        if ($LocalGuest.Enabled)
            {
                "LOCAL GUEST ACCOUNT ENABLED: YES" | Tee-Object -FilePath $GlobalOutputFile -Append
            }
        else 
            {
                "LOCAL GUEST ACCOUNT ENABLED: NO" | Tee-Object -FilePath $GlobalOutputFile -Append
            }
    }
else 
    {
        "LOCAL GUEST ACCOUNT ENABLED: UNKNOWN (NO LOCAL ACCOUNT WITH RID 501)" | Tee-Object -FilePath $GlobalOutputFile -Append
    }


### Check if any local users have a blank password (this is only for local accounts, not domain accounts)
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"CHECK LOCAL USERS FOR BLANK PASSWORDS: ******************************" | Tee-Object -FilePath $GlobalOutputFile -Append
$LocalUsersWithBlankPasswords = $LocalUsers | Where-Object {($_.PasswordLastSet -eq $null) -and ($_.Enabled -eq $true)}
if ($LocalUsersWithBlankPasswords)
    {
        "LOCAL USERS WITH BLANK PASSWORDS: YES" | Tee-Object -FilePath $GlobalOutputFile -Append
        $LocalUsersWithBlankPasswords | Select-Object -Property Name, SID | Sort-Object -Property Name | Tee-Object -FilePath $GlobalOutputFile -Append
    }
else 
    {
        "LOCAL USERS WITH BLANK PASSWORDS: NO" | Tee-Object -FilePath $GlobalOutputFile -Append
    }



### Get local groups
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"LOCAL GROUPS: ******************************" | Tee-Object -FilePath $GlobalOutputFile -Append
$LocalGroups = Get-LocalGroup | Sort-Object -Property Name 
$LocalGroups | Select-Object -Property Name, SID | Sort-Object -Property Name | Tee-Object -FilePath $GlobalOutputFile -Append
$LocalGroups | Select-Object -Property * | Sort-Object -Property Name | Export-Csv -Path $OutputFile_LocalGroups

### Get local group members
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"LOCAL GROUP MEMBERS: ***********************" | Tee-Object -FilePath $GlobalOutputFile -Append
Foreach ($LocalGroup in $LocalGroups)
    {
        "Group: $LocalGroup" | Tee-Object -FilePath $GlobalOutputFile -Append
        $GroupMembers = Get-LocalGroupMember -Group $LocalGroup | Select-Object -ExpandProperty Name

          if ($GroupMembers)
            {

                Foreach ($GroupMember in $GroupMembers)
                    {
                        "    - Member: $GroupMember" | Tee-Object -FilePath $GlobalOutputFile -Append
                    }
            }
        else 
            {
                "    - No Members" | Tee-Object -FilePath $GlobalOutputFile -Append
            }
        
        # "`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
        
    }


### Get local profile folders
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"LOCAL PROFILE FOLDERS: ****************************" | Tee-Object -FilePath $GlobalOutputFile -Append
$UserProfiles = Get-CimInstance -ClassName Win32_UserProfile
$UserProfiles | Select-Object -Property SID, LocalPath, LastUseTime | Format-Table | Tee-Object -FilePath $GlobalOutputFile -Append

### Get local profiles in registry
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"LOCAL PROFILES IN REGISTRY: ***********************" | Tee-Object -FilePath $GlobalOutputFile -Append
Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" | Select-Object -ExpandProperty PSChildName | Tee-Object -FilePath $GlobalOutputFile -Append

### Get patch (hotfix) info
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"OS PATCHES: ******************************" | Tee-Object -FilePath $GlobalOutputFile -Append
$Hotfixes | Sort-Object -Property InstalledOn -Descending | Select-Object -Property HotfixID, Description, Caption, InstalledOn | Tee-Object -FilePath $GlobalOutputFile -Append

### Get Last Patch Date
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"LAST PATCH DATE: ******************************" | Tee-Object -FilePath $GlobalOutputFile -Append
$Today = Get-Date
$LastInstalledPatch = $Hotfixes | Sort-Object -Property InstalledOn -Descending | Select-Object -First 1 -ExpandProperty InstalledOn
$DaysSincePatched = ($Today - $LastInstalledPatch).Days
"LAST PATCH INSTALLED: $LastInstalledPatch" | Tee-Object -FilePath $GlobalOutputFile -Append
"DAYS SINCE LAST PATCH: $DaysSincePatched" | Tee-Object -FilePath $GlobalOutputFile -Append

if ($DaysSincePatched -gt 45)
    {
        "SYSTEM IS LIKELY VULNERABLE TO KNOWN EXPLOITS: YES" | Tee-Object -FilePath $GlobalOutputFile -Append
    }
else 
    {
        "SYSTEM IS LIKELY VULNERABLE TO KNOWN EXPLOITS: NO" | Tee-Object -FilePath $GlobalOutputFile -Append
    }


### Get last 20 setup events
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"LAST 20 Setup Log Events: ****************" | Tee-Object -FilePath $GlobalOutputFile -Append
Get-WinEvent -LogName Setup -MaxEvents 20 | Select-Object -Property TimeCreated, Message | Format-List | Tee-Object -FilePath $GlobalOutputFile -Append

## Get Installed Software
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"INSTALLED SOFTWARE:**********************" | Tee-Object -FilePath $GlobalOutputFile -Append
"PATH: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" | Tee-Object -FilePath $GlobalOutputFile -Append
$Software = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" | Get-ItemProperty -Name DisplayName, DisplayVersion -ErrorAction SilentlyContinue | Select-Object -Property DisplayName, DisplayVersion | Sort-Object -Property DisplayName
$Software | Tee-Object -FilePath $GlobalOutputFile -Append
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"PATH: HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" | Tee-Object -FilePath $GlobalOutputFile -Append
$Software = Get-ChildItem -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" | Get-ItemProperty -Name DisplayName, DisplayVersion -ErrorAction SilentlyContinue | Select-Object -Property DisplayName, DisplayVersion | Sort-Object -Property DisplayName
$Software | Tee-Object -FilePath $GlobalOutputFile -Append
 
### Get environment variables
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"OS ENVIRONMENTAL VARIABLES: **************" | Tee-Object -FilePath $GlobalOutputFile -Append
Get-ChildItem -Path Env:\ | Select-Object -Property Name, Value | Sort-Object -Property Name  | Format-List | Tee-Object -FilePath $GlobalOutputFile -Append

### Get logged on users
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"LOGGED IN USERS: *************************" | Tee-Object -FilePath $GlobalOutputFile -Append
C:\windows\System32\qwinsta.exe | Tee-Object -FilePath $GlobalOutputFile -Append

Get-CimInstance -ClassName Win32_LoggedOnUser | Select-Object -Property Antecedent, Dependent | Format-List | Tee-Object -FilePath $GlobalOutputFile -Append

### Get SMB Mapped Drives
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"SMB MAPPED DRIVES: ******************************" | Tee-Object -FilePath $GlobalOutputFile -Append
$MappedDrives = Get-SmbMapping 

if ($MappedDrives -ne $null)
    {
        $MappedDrives| Select-Object -Property LocalPath, RemotePath, UserName, Status | Sort-Object -Property LocalPath | Tee-Object -FilePath $GlobalOutputFile -Append
        $MappedDrives | Select-Object -Property * | Sort-Object -Property LocalPath | Export-Csv -Path "$WorkingDirectory\$env:ComputerName-$DNSDomain-$FileNameDate-Triage-SMBMappedDrives.csv" -Delimiter "," -NoTypeInformation 
    }
else 
    {
        "No mapped drives found" | Tee-Object -FilePath $GlobalOutputFile -Append
    }

### Get SMB shares
$Shares = Get-SmbShare
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"SMB SHARES: ******************************" | Tee-Object -FilePath $GlobalOutputFile -Append
$Shares | Tee-Object -FilePath $GlobalOutputFile -Append

### Get SMB shares access
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"SMB SHARE PERMS: *************************" | Tee-Object -FilePath $GlobalOutputFile -Append
$Shares | Get-SmbShareAccess | Sort-Object -Property Name | Tee-Object -FilePath $GlobalOutputFile -Append

### Get HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Registry entries
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"REGISTRY KEY (HKLM RUN): *************************" | Tee-Object -FilePath $GlobalOutputFile -Append
$AllRegKeys=@()
$RegKeys = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" 
$RegKeys | Tee-Object -FilePath $GlobalOutputFile -Append
$AllRegKeys += $RegKeys
Start-Process -FilePath "C:\windows\System32\reg.exe" -ArgumentList "export HKLM\Software\Microsoft\Windows\CurrentVersion\Run $WorkingDirectory\HKLM_Run.reg /y"

###Get HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\ Registry entries
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"REGISTRY KEY (HKLM RUN ONCE): *********************" | Tee-Object -FilePath $GlobalOutputFile -Append
$RegKeys = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" 
$RegKeys | Tee-Object -FilePath $GlobalOutputFile -Append
$AllRegKeys += $RegKeys
Start-Process -FilePath "C:\windows\System32\reg.exe" -ArgumentList "export HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce $WorkingDirectory\HKLM_RunOnce.reg /y"

### Get HKU Registry entries

### TypedPaths is a Windows Registry key that records the last 25 paths typed or inserted into the path bar of File Explorer (previously known as Windows Explorer). 
### The typed paths, however, do not appear instantly within the TypedPaths key. The user has to close the File Explorer window for the typed paths to be committed to the registry 

### TypedURLs is a Windows Registry key that is similar in concept to TypedPaths key. The key records URLs typed or inserted in the Internet Explorer (IE) address bar. 
### URLs that are completed by the browser’s AutoComplete functionality are not recorded in the key unless the website was previously visited by the user.

$InterestingRegKeys=@("SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "software\microsoft\Software\Microsoft\InternetExplorer\TypedURLs", "software\microsoft\windows\currentversion\explorer\typedpaths")

"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"USER REGISTRY KEYS: ***********************" | Tee-Object -FilePath $GlobalOutputFile -Append

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
            "USERNAME ($($UserProfile.SID))  REGISTRY KEYS: ***********************" | Tee-Object -FilePath $GlobalOutputFile -Append
            
            #Loop through all the interesting keys
            $AllRunRegKeys = @()
            Foreach($InterestingRegKey in $InterestingRegKeys)
                {
                    "`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
                    "USER: ($($UserProfile.SID)) REGISTRY KEY: $InterestingRegKey ***********************" | Tee-Object -FilePath $GlobalOutputFile -Append

                    #Last get the last part of the registry key for use in the file name of the exported key
                    $ShortKeyNameStart = $InterestingRegKey.LastIndexOf("\") + 1
                    $ShortKeyName = $InterestingRegKey.Substring($ShortKeyNameStart)

                    $RegKeys = Get-ItemProperty -Path Registry::"HKEY_USERS\$($UserProfile.SID)\$InterestingRegKey" 
                    #Save the user registry key to log file
                    $RegKeys | Tee-Object -FilePath $GlobalOutputFile -Append
                    $AllRunRegKeys += $RegKeys
                    #Export out the registry key
                    Start-Process -FilePath "C:\windows\System32\reg.exe" -ArgumentList "export HKU\$($UserProfile.SID)\$InterestingRegKey $WorkingDirectory\$ShortName-$ShortKeyName.reg /y" -Wait
                }
            
        }
        
    }

### Get Named Pipes
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"NAMED PIPES: ******************************" | Tee-Object -FilePath $GlobalOutputFile -Append
[System.IO.Directory]::GetFiles("\\.\\pipe\\") | Sort-Object | Tee-Object -FilePath $GlobalOutputFile -Append

### Get System Drivers
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"SYSTEM DRIVERS: ******************************" | Tee-Object -FilePath $GlobalOutputFile -Append
$SystemDrivers = Get-CimInstance -ClassName Win32_SystemDriver
$SystemDrivers | Select-Object -Property Name, DisplayName, State, StartMode, PathName | Sort-Object -Property Name | Format-List | Tee-Object -FilePath $GlobalOutputFile -Append
$SystemDrivers | Select-Object -Property * | Sort-Object -Property Name | Export-Csv -Path $OutputFile_SystemDrivers -Delimiter "," -NoTypeInformation


### Get startup command items
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"STARTUP COMMANDS: ************************" | Tee-Object -FilePath $GlobalOutputFile -Append
$StartupCmds = Get-CimInstance -ClassName Win32_StartupCommand
$StartupCmds | Export-Csv -Path $StartupCmdsPath
$StartupCmds | Select-Object -Property Name, Command, Location | Tee-Object -FilePath $GlobalOutputFile -Append

### Get startup command hashes
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"STARTUP COMMANDS HASHES: ******************" | Tee-Object -FilePath $GlobalOutputFile -Append
$StartupCmdExes = $StartupCmds | Select-Object -ExpandProperty Command
Get-HashesOfExes -ExecutablesToHash $StartupCmdExes -Verbose -HashOutputFilePath $StartupCmdHashesPath

### Get all services
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"SERVICES: ******************************" | Tee-Object -FilePath $GlobalOutputFile -Append
$Services = Get-CimInstance -ClassName Win32_Service | Select-Object -Property Name,DisplayName, Started, StartMode, PathName
$Services | Export-Csv -Path $ServicesPath 
$Services | Format-Table | Tee-Object -FilePath $GlobalOutputFile -Append

### Get hashes for services
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"SERVICE HASHES: *****************" | Tee-Object -FilePath $GlobalOutputFile -Append
$ServiceExes = $Services | Select-Object -ExpandProperty PathName | Sort-Object -Property PathName
Get-HashesOfExes -ExecutablesToHash $ServiceExes -Verbose -HashOutputFilePath $ServicesHashesPath

### Get scheduled tasks descriptions
$ScheduledTasks = Get-ScheduledTask
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"SCHEDULED TASKS: ***********************" | Tee-Object -FilePath $GlobalOutputFile -Append
$ScheduledTasks | Export-Csv -Path $ScheduledTasksPath
$ScheduledTasks | Select-Object -Property TaskName, State, Description | Sort-Object -Property TaskName | Format-Table | Tee-Object -FilePath $GlobalOutputFile -Append

### Get scheduled tasks actions
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"SCHEDULED TASKS ACTIONS: ****************" | Tee-Object -FilePath $GlobalOutputFile -Append
$ScheduledTaskActions = $ScheduledTasks | Select-Object -ExpandProperty Actions | Select-Object -Property Execute, Arguments -Unique
$ScheduledTaskActions | Export-Csv -Path $ScheduledTasksActionsPaths
$ScheduledTaskActions | Tee-Object -FilePath $GlobalOutputFile -Append

### Get hashes for scheduled task actions
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"SCHEDULED TASKS HASHES: *****************" | Tee-Object -FilePath $GlobalOutputFile -Append
$ScheduledTaskActionExes = $ScheduledTaskActions | Select-Object -ExpandProperty Execute
Get-HashesOfExes -ExecutablesToHash $ScheduledTaskActionExes  -Verbose -HashOutputFilePath $ScheduledTaskHashesPath

### Get running processes
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"RUNNING PROCESSES: *********************" | Tee-Object -FilePath $GlobalOutputFile -Append
$Processes = Get-CimInstance -Query "Select * from win32_process"
$ProcessInfo = $Processes | Select-Object Name, ProcessId, @{Label="Owner";Expression={$_.GetOwner()}}, CommandLine 
$ProcessInfo | Export-Csv -Path $ProcessPath
$ProcessInfo | Format-Table | Tee-Object -FilePath $GlobalOutputFile -Append

### Get running process hashes
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"RUNNING PROCESSES HASHES:****************" | Tee-Object -FilePath $GlobalOutputFile -Append
$CommandLines = $Processes | Select-Object -ExpandProperty ExecutablePath -Unique | Sort-Object -Unique
Get-HashesOfExes -ExecutablesToHash $CommandLines -Verbose -HashOutputFilePath $ProcessHashesPath

### Save list of all (service, processes, scheduled tasks) executables hashes to a file in case we want to iterate over the file and send to Virus Total etc....
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"ALL IMPORTANT PROCESSES HASHES:****************" | Tee-Object -FilePath $GlobalOutputFile -Append
$AllExes | Out-File -FilePath $AllExesPath
if (Test-Path -Path $AllExesPath)
    {
        if((Get-content -Path $AllExesPath).length -gt 10)
            {
                "Wrote All Service/Process/Scheduled Task/Startup Exes To $AllExesPath" | Tee-Object -FilePath $GlobalOutputFile -Append
            }
    }


###Check if each process, scheduled task, service, startup command etc is signed
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"CHECK SIGNATURES ON EXEs: *********************" | Tee-Object -FilePath $GlobalOutputFile -Append
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
                        "Unsigned Exe or Invalid Signature: $AExe" | Tee-Object -FilePath $GlobalOutputFile -Append
                        
                        ##Write filepath, signature.status to unsigned exe .csv
                    }
            }
        else 
            {
              ##Any paths that fail??
              "Failed to test signature on: $AExe" | Tee-Object -FilePath $GlobalOutputFile -Append

            }
    }

$UnsignedExes | Export-Csv -Path $UnsignedExesPath

### Make sure eventlogs are enabled
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"EVENT LOG ENABLED: *********************" | Tee-Object -FilePath $GlobalOutputFile -Append
$LogNames = @("Security","Application","Setup","System")
Foreach ($LogName in $LogNames)
    {
        $LogObj = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $LogName

        "Windows Event Log: $LogName is enabled: $($LogObj.IsEnabled)" | Tee-Object -FilePath $GlobalOutputFile -Append 
    }


### Backup event logs
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"EVENT LOG BACKUP: *********************" | Tee-Object -FilePath $GlobalOutputFile -Append
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
                        "Backed Up $LogName log to $BackupDestinationPath" | Tee-Object -FilePath $GlobalOutputFile -Append
                    }
            }
    }

 
### Zip up event logs
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"ZIP UP EVENT LOGS (.EVTX): *********************" | Tee-Object -FilePath $GlobalOutputFile -Append
$CompressSettings = @{
    Path = "$WorkingDirectory\*.evtx"
    CompressionLevel = "Optimal"
    DestinationPath = $ZippedEventLogsPath
}

Compress-Archive @CompressSettings

if(Test-Path -Path $ZippedEventLogsPath )
    {
        "Zipped Up Event Logs (.EVTX) to $ZippedEventLogsPath" | Tee-Object -FilePath $GlobalOutputFile -Append
         Remove-Item -Path "$WorkingDirectory\*.evtx" -Force
    }



### Get Windows Firewall Status


### Get GPRESULTS
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"GATHER GPRESULTS: *********************" | Tee-Object -FilePath $GlobalOutputFile -Append
Start-Process -FilePath "C:\Windows\System32\gpresult.exe" -ArgumentList "/H $GPResultsPath" -Wait

If (Test-Path -Path $GPResultsPath)
    {
        "GPResults saved to $GPResultsPath" | Tee-Object -FilePath $GlobalOutputFile -Append
    }



### Zip up all the csv output
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"ZIP UP CSV FILES: *********************" | Tee-Object -FilePath $GlobalOutputFile -Append
$CompressSettings = @{
    Path = @("$WorkingDirectory\*.csv", "$WorkingDirectory\*.html", "$WorkingDirectory\*.txt", "$WorkingDirectory\*.reg")
    CompressionLevel = "Optimal"
    DestinationPath = $ZippedOutputPath
}

Compress-Archive @CompressSettings

if(Test-Path -Path $ZippedOutputPath)
    {
        "Zipped Up CSVs to $ZippedOutputPath" | Tee-Object -FilePath $GlobalOutputFile -Append
        Remove-Item -Path "$WorkingDirectory\*.csv" -Force
        Remove-Item -Path "$WorkingDirectory\*.html" -Force
        Remove-Item -Path "$WorkingDirectory\*.reg" -Force
    }



#Script complete
"`n`n" | Tee-Object -FilePath $GlobalOutputFile -Append
"SCRIPT COMPLETE:*************************"  | Tee-Object -FilePath $GlobalOutputFile -Append
$FileDate = Get-Date -Format "MM/dd/yy hh:mm:ss tt"
"COMPLETED AT: $FileDate $TimeZone"    | Tee-Object -FilePath $GlobalOutputFile -Append