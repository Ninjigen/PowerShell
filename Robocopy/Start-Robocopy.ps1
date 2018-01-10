<#
.SYNOPSIS
RoboCopy with PowerShell progress.
.DESCRIPTION
Performs file copy with RoboCopy. Output from RoboCopy is captured,
parsed, and returned as Powershell native status and progress.
.PARAMETER Source
Source folder (must be a folder)
.PARAMETER Destination
Destination folder (must be a folder)
.OUTPUTS
Returns an object with the status of final copy.
REMINDER: Any error level below 8 can be considered a success by RoboCopy.
.EXAMPLE
C:\PS> .\Start-Robocopy -Source "c:\Src" -Destination "d:\Dest" [-Files 'file1.ext1' '*.ext2'] [-IS] [-IT]
Copy the contents of the c:\Src directory to a directory d:\Dest
Without the /e or /mir switch, only files from the root of c:\src are copied.
See https://technet.microsoft.com/en-us/library/cc733145(v=ws.11).aspx for an extensive documentation on Robocopy switches
The following switches can't be used : 
 - Logging Options
 - Job Options
.LINK
https://github.com/Ninjigen/PowerShell/tree/master/Robocopy
.NOTES
Original script by Keith S. Garner (KeithGa@KeithGa.com) - 6/23/2014
Originally posted on https://keithga.wordpress.com/2014/06/23/copy-itemwithprogress
With inspiration by Trevor Sullivan @pcgeek86
Updated by Ninjigen - 01/08/2018
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$True)]
    [String]$Source,
    [Parameter(Mandatory=$True)]
    [String]$Destination,
    [Parameter(Mandatory=$False)] 
    [String[]] $Files,
    [Parameter(Mandatory=$False)]
    [String]$LogFile,
    [Alias('s')]
    [switch]$IncludeSubDirectories,
    [Alias('e')]
    [switch]$IncludeEmptySubDirectories,
    [Parameter(Mandatory=$False)]
    [Alias('lev')]
    [Int]$Level,
    [Alias('b')]
    [switch]$BackupMode,
    [Alias('z')]
    [switch]$RestartMode,
    [switch]$EFSRaw,
    [Parameter(Mandatory=$False)]
    [Alias('copy')]
    [ValidateSet('D','A','T','S','O','U')]
    [String[]]$CopyFlags,
    [switch]$NoCopy,
    [Alias('secfix')]
    [switch]$SecurityFix,
    [Alias('timfix')]
    [switch]$Timefix,
    [switch]$Purge,
    [Alias('mir')]
    [switch]$Mirror,
    [Alias('mov')]
    [switch]$MoveFiles,
    [Alias('move')]
    [switch]$MoveFilesAndDirectories,
    [Parameter(Mandatory=$False)]
    [ValidateSet('R','A','S','H','N','E','T')]
    [String[]]$AddAttribute,
    [Parameter(Mandatory=$False)]
    [ValidateSet('R','A','S','H','N','E','T')]
    [String[]]$RemoveAttribute,
    [switch]$Create,
    [switch]$fat,
    [switch]$IgnoreLongPath,
    [Parameter(Mandatory=$False)]
    [Alias('mon')]
    [Int]$MonitorChanges,
    [Parameter(Mandatory=$False)]
    [Alias('mot')]
    [Int]$MonitorMinutes,
    [Parameter(Mandatory=$False)]
    [Alias('MT')]
    [Int]$Threads,
    [Parameter(Mandatory=$False)]
    [Alias('rh')]
    [String]$RunTimes,
    [Alias('pf')]
    [switch]$UsePerFileRunTimes,
    [Parameter(Mandatory=$False)]
    [Alias('ipg')]
    [Int]$InterPacketGap,
    [Alias('sl')]
    [switch]$SymbolicLink,
    [Alias('a')]
    [switch]$Archive,
    [Alias('m')]
    [switch]$ResetArchiveAttribute,
    [Parameter(Mandatory=$False)]
    [Alias('ia')]
    [ValidateSet('R','A','S','H','N','E','T','O')]
    [String[]]$IncludeAttribute,
    [Parameter(Mandatory=$False)]
    [ValidateSet('R','A','S','H','N','E','T','O')]
    [Alias('xa')]
    [String[]]$ExcludeAttribute,
    [Parameter(Mandatory=$False)]
    [Alias('xf')]
    [String[]]$ExcludeFileName,
    [Parameter(Mandatory=$False)]
    [Alias('xd')]
    [String[]]$ExcludeDirectory,
    [Alias('xct')]
    [switch]$ExcludeChangedFiles,
    [Alias('xn')]
    [switch]$ExcludeNewerFiles,
    [Alias('xo')]
    [switch]$ExcludeOlderFiles,
    [Alias('xx')]
    [switch]$ExcludeExtraFiles,
    [Alias('xl')]
    [switch]$ExcludeLonelyFiles,
    [Alias('is')]
    [switch]$IncludeSameFiles,
    [Alias('it')]
    [switch]$IncludeTweakedFiles,
    [Parameter(Mandatory=$False)]
    [Alias('max')]
    [String]$MaximumFileSize,
    [Parameter(Mandatory=$False)]
    [Alias('min')]
    [String]$MinimumFileSize,
    [Parameter(Mandatory=$False)]
    [Alias('maxage')]
    [String]$MaximumFileAge,
    [Parameter(Mandatory=$False)]
    [Alias('minage')]
    [String]$MinimumFileAge,
    [Parameter(Mandatory=$False)]
    [Alias('maxlad')]
    [String]$MaximumFileLastAccessDate,
    [Parameter(Mandatory=$False)]
    [Alias('minlad')]
    [String]$MinimumFileLastAccessDate,
    [Alias('xj')]
    [switch]$ExcludeJunctionPoints,
    [Alias('xjf')]
    [switch]$ExcludeFileJunctionPoints,
    [Alias('xdj')]
    [switch]$ExcludeDirectoryJunctionPoints,
    [Alias('fft')]
    [switch]$AssumeFATFileTime,
    [Alias('dst')]
    [switch]$CompensateDST,
    [Parameter(Mandatory=$False)]
    [Alias('r')]
    [Int]$Retry,
    [Parameter(Mandatory=$False)]
    [Alias('w')]
    [Int]$Wait,
    [Alias('reg')]
    [switch]$SaveRetrySettings,
    [Alias('tbd')]
    [switch]$WaitForShareName
)

Function Format-SpeedHumanReadable {
<#
    .SYNOPSIS
    Changes a file size in Bytes into a more readable format
#>
    Param (
        [String]$size
    )
    [System.Double]$absSize=$size.trimStart('-')
    if ($size -like '-*') {$Operator='-'}
    else {$Operator=''}
    switch ($absSize) {
        {$_ -ge 1PB}{"{1}{0:#.#' PB'}" -f ($absSize / 1PB),$Operator; break}
        {$_ -ge 1TB}{"{1}{0:#.#' TB'}" -f ($absSize / 1TB),$Operator; break}
        {$_ -ge 1GB}{"{1}{0:#.#' GB'}" -f ($absSize / 1GB),$Operator; break}
        {$_ -ge 1MB}{"{1}{0:#.#' MB'}" -f ($absSize / 1MB),$Operator; break}
        {$_ -ge 1KB}{"{1}{0:#' KB'}" -f ($absSize / 1KB),$Operator; break}
        default {"{1}{0}" -f ($absSize),$Operator + " B"}
    }
}

$RobocopyArguments = $Source,$Destination + $Files

$SourceItem = Get-Item -Path $Source -ErrorAction Stop
if ($SourceItem.Attributes -eq 'Archive') {
	throw ('InvalidParameterException : [{0}] is not a directory. The Source parameter must be a directory' -f $Source)
}

$DestinationItem = Get-Item -Path $Destination -ErrorAction Stop
if ($DestinationItem.Attributes -eq 'Archive') {
	throw ('InvalidParameterException : [{0}] is not a directory. The Destination parameter must be a directory' -f $Destination)
}

if ($IncludeSubDirectories) {$RobocopyArguments += '/s'}
if ($IncludeEmptySubDirectories) {$RobocopyArguments += '/e'}
if ($Level) {$RobocopyArguments += '/lev:' + $Level}
if ($BackupMode) {$RobocopyArguments += '/b'}
if ($RestartMode) {$RobocopyArguments += '/z'}
if ($EFSRaw) {$RobocopyArguments += '/efsraw'}
if ($CopyFlags) {$RobocopyArguments += '/copy:' + (($CopyFlags | Sort -Unique) -join '')}
if ($NoCopy) {$RobocopyArguments += '/nocopy'}
if ($SecurityFix) {$RobocopyArguments += '/secfix'}
if ($Timefix) {$RobocopyArguments += '/timfix'}
if ($Purge) {$RobocopyArguments += '/purge'}
if ($Mirror) {$RobocopyArguments += '/mir'}
if ($MoveFiles) {$RobocopyArguments += '/mov'}
if ($MoveFilesAndDirectories) {$RobocopyArguments += '/move'}
if ($AddAttribute) {$RobocopyArguments += '/a+:' + (($AddAttribute | Sort -Unique) -join '')}
if ($RemoveAttribute) {$RobocopyArguments += '/a-:' + (($RemoveAttribute | Sort -Unique) -join '')}
if ($Create) {$RobocopyArguments += '/create'}
if ($fat) {$RobocopyArguments += '/fat'}
if ($IgnoreLongPath) {$RobocopyArguments += '/256'}
if ($MonitorChanges) {$RobocopyArguments += '/mon:' + $MonitorChanges}
if ($MonitorMinutes) {$RobocopyArguments += '/mot:' + $MonitorMinutes}
if ($Threads) {$RobocopyArguments += '/MT:' + $Threads}
if ($RunTimes) {$RobocopyArguments += '/rh:' + $RunTimes}
if ($UsePerFileRunTimes) {$RobocopyArguments += '/pf'}
if ($InterPacketGap) {$RobocopyArguments += '/ipg:' + $InterPacketGap}
if ($SymbolicLink) {$RobocopyArguments += '/sl'}
if ($Archive) {$RobocopyArguments += '/a'}
if ($ResetArchiveAttribute) {$RobocopyArguments += '/m'}
if ($IncludeAttribute) {$RobocopyArguments += '/ia:' + ($IncludeAttribute | Sort -Unique) -join ''}
if ($ExcludeAttribute) {$RobocopyArguments += '/xa:' + ($ExcludeAttribute | Sort -Unique) -join ''}
if ($ExcludeFileName) {$RobocopyArguments += '/xf ' + $ExcludeFileName -join ' '}
if ($ExcludeDirectory) {$RobocopyArguments += '/xd ' + $ExcludeDirectory -join ' '}
if ($ExcludeChangedFiles) {$RobocopyArguments += '/xct'}
if ($ExcludeNewerFiles) {$RobocopyArguments += '/xn'}
if ($ExcludeOlderFiles) {$RobocopyArguments += '/xo'}
if ($ExcludeExtraFiles) {$RobocopyArguments += '/xx'}
if ($ExcludeLonelyFiles) {$RobocopyArguments += '/xl'}
if ($IncludeSameFiles) {$RobocopyArguments += '/is'}
if ($IncludeTweakedFiles) {$RobocopyArguments += '/it'}
if ($MaximumFileSize) {$RobocopyArguments += '/max:' + $MaximumFileSize}
if ($MinimumFileSize) {$RobocopyArguments += '/min:' + $MinimumFileSize}
if ($MaximumFileAge) {$RobocopyArguments += '/maxage:' + $MaximumFileAge}
if ($MinimumFileAge) {$RobocopyArguments += '/minage:' + $MinimumFileAge}
if ($MaximumFileLastAccessDate) {$RobocopyArguments += '/maxlad:' + $MaximumFileLastAccessDate}
if ($MinimumFileLastAccessDate) {$RobocopyArguments += '/minlad:' + $MinimumFileLastAccessDate}
if ($ExcludeJunctionPoints) {$RobocopyArguments += '/xj'}
if ($ExcludeFileJunctionPoints) {$RobocopyArguments += '/xjf'}
if ($ExcludeDirectoryJunctionPoints) {$RobocopyArguments += '/xjd'}
if ($AssumeFATFileTime) {$RobocopyArguments += '/fft'}
if ($CompensateDST) {$RobocopyArguments += '/dst'}
if ($Retry) {$RobocopyArguments += '/r:' + $Retry}
if ($Wait) {$RobocopyArguments += '/w:' + $Wait}
if ($SaveRetrySettings) {$RobocopyArguments += '/reg'}
if ($WaitForShareName) {$RobocopyArguments += '/tbd'}

# Path of the log files used to scan the robocopy progress
## creates a temporary disposable file under the %TEMP% directory with a serial generic name
### File used to audit the number of files to be copied and the total file size
$ScanLog  = [IO.Path]::GetTempFileName()
## creates a temporary file to monitor the progress of the copy
### this file is to be disposed unless the $LogFile parameter is used
if ($LogFile) {
    $RoboLog  = $LogFile
    $DisposeRoboLog = $False
} else {
    $RoboLog  = [IO.Path]::GetTempFileName()
    $DisposeRoboLog = $True
}

# Arguments of the scan (audit) command. Fills in the $ScanLog temp file
$ScanArgs = $RobocopyArguments + "/ndl /TEE /bytes /Log:$ScanLog /nfl /L".Split(" ")

# Arguments of the copy command. Fills in the $RoboLog temp file
$RoboArgs = $RobocopyArguments + "/ndl /TEE /bytes /Log:$RoboLog /NC".Split(" ")

# Launch Robocopy Processes
write-verbose ("Robocopy Scan:`n" + ($ScanArgs -join " "))
write-verbose ("Robocopy Full:`n" + ($RoboArgs -join " "))

#Runs the scan command in a separate process, then pass through the result in the $ScanRun variable
$ScanRun = Start-Process robocopy -PassThru -WindowStyle Hidden -ArgumentList $ScanArgs

#Runs the copy command in a separate process, then pass through the result in the $RoboRun variable
$RoboRun = Start-Process robocopy -PassThru -WindowStyle Hidden -ArgumentList $RoboArgs

# Parse Robocopy "Scan" pass
$ScanRun.WaitForExit()
$LogData = Get-Content $ScanLog
if ($ScanRun.ExitCode -ge 8) {
    $LogData|out-string|Write-Error
    # Throws an error if the scan fails
    throw "Robocopy $($ScanRun.ExitCode)"
}

# Find out the total data size to transfer with the scan log file
$FileSize = [regex]::Match($LogData[-4],".+:\s+(\d+)\s+(\d+)").Groups[2].Value
write-verbose ("Robocopy Bytes: $FileSize `n" +($LogData -join "`n"))

# Monitor Full RoboCopy
while (!$RoboRun.HasExited) {
    $LogData = get-content $RoboLog
    $Files = $LogData -match "^\s*(\d+)\s+(\S+)"
    if ($Files -ne $Null ) {
        if ($Files.count -eq 1) {
            $copied = $Files.split("`t")[-2]
        } else {
            $copied = ($Files[0..($Files.Length-2)] | %{$_.Split("`t")[-2]} | Measure -sum).Sum
        }
        if ($LogData[-1] -match "(100|\d?\d\.\d)\%") {
            # Write-Host "Fin"
            Write-Progress Copy -ParentID $RoboRun.ID -percentComplete $LogData[-1].Trim("% `t") $LogData[-1]
            if ($Files.count -eq 1) {
                $copied = $Files.split("`t")[-2] /100 * ($LogData[-1].trim("% `t"))
            }
            else {
                $copied += $Files[-1].Split("`t")[-2] /100 * ($LogData[-1].Trim("% `t"))
            }
        }
        else {
            Write-Progress Copy -ParentID $RoboRun.ID -Complete
        }
        Write-Progress -Activity ('ROBOCOPY [{0}] --> [{1}]' -f $SourceItem.FullName,$DestinationItem.FullName) -ID $RoboRun.ID -PercentComplete ($copied/$FileSize*100) -Status $Files[-1].Split("`t")[-1]
    }
}

# Parse full RoboCopy pass results, and cleanup
$RoboLogResult = (get-content $RoboLog)[-11..-2]
$RoboLogResult | out-string | Write-Verbose
$Speed,$trash = [regex]::Match($RoboLogResult[7],'\d+').Groups[0].Value
[TimeSpan]$TotalDuration,[TimeSpan]$CopyDuration,[TimeSpan]$FailedDuration,[TimeSpan]$ExtraDuration,$trash = $RoboLogResult[4] | Select-String -Pattern '\d?\d\:\d{2}\:\d{2}' -AllMatches | Foreach-Object {$_.Matches} | Foreach-Object {$_.Value}
$TotalDirs,$TotalDirCopied,$TotalDirIgnored,$TotalDirMismatched,$TotalDirFailed,$TotalDirExtra,$trash = $RoboLogResult[1] | Select-String -Pattern '\d+' -AllMatches | Foreach-Object {$_.Matches} | Foreach-Object {$_.Value}
$TotalFiles,$TotalFileCopied,$TotalFileIgnored,$TotalFileMismatched,$TotalFileFailed,$TotalFileExtra,$trash = $RoboLogResult[2] | Select-String -Pattern '\d+' -AllMatches | Foreach-Object {$_.Matches} | Foreach-Object {$_.Value}


# Manages the success/ERROR message according to the Exit code
switch ($RoboRun.ExitCode) {
     0 {$Message = 'SUCCESS - No errors occurred, and no copying was done. The source and destination directory trees are completely synchronized.'}
     1 {$Message = 'SUCCESS - One or more files were copied successfully.'}
     2 {$Message = 'SUCCESS - Some Extra files or directories were detected. No files were copied'}
     3 {$Message = 'SUCCESS - Some files were copied. Additional files were present. No failure was encountered'}
     4 {$Message = 'SUCCESS - Some Mismatched files or directories were detected.'}
     5 {$Message = 'SUCCESS - Some files were copied. Some files were mismatched. No failure was encountered.'}
     6 {$Message = 'SUCCESS - Additional files and mismatched files exist. No files were copied and no failures were encountered.
             (the files already exist in the destination directory)'}
     7 {$Message = 'SUCCESS - Files were copied, a file mismatch was present, and additional files were present.'}
     8 {$Message = 'FAILURE - Some files or directories could not be copied (copy errors occurred and the retry limit was exceeded).'}
     9 {$Message = 'FAILURE - Some files or directories could not be copied (copy errors occurred and the retry limit was exceeded).'}
    10 {$Message = 'FAILURE - Some files or directories could not be copied (copy errors occurred and the retry limit was exceeded). Some Extra files or directories were detected.'}
    11 {$Message = 'FAILURE - Some files or directories could not be copied (copy errors occurred and the retry limit was exceeded). Some Extra files or directories were detected.'}
    12 {$Message = 'FAILURE - Some files or directories could not be copied (copy errors occurred and the retry limit was exceeded). Some Extra files or directories were detected. Some Mismatched files or directories were detected.'}
    13 {$Message = 'FAILURE - Some files or directories could not be copied (copy errors occurred and the retry limit was exceeded). Some Extra files or directories were detected. Some Mismatched files or directories were detected.'}
    14 {$Message = 'FAILURE - Some files or directories could not be copied (copy errors occurred and the retry limit was exceeded). Some Extra files or directories were detected.'}
    15 {$Message = 'FAILURE - Some files or directories could not be copied (copy errors occurred and the retry limit was exceeded). Some Extra files or directories were detected. Some Mismatched files or directories were detected.'}
    16 {$Message = 'FAILURE - Serious error. Robocopy did not copy any files. Either a usage error or an error due to insufficient access privileges on the source or destination directories.'}
}

$Property = [ordered]@{
    'Source' = $Source
    'Destination' = $Destination
    'Command' = "Robocopy.exe " + ($RoboArgs -join " ");
    'DirCount' = $TotalDirs;
    'FileCount' = $TotalFiles;
    'Duration' = $TotalDuration;
    'DirCopied' = $TotalDirCopied;
    'FileCopied' = $TotalFileCopied;
    'CopyDuration' = $CopyDuration
    'DirIgnored' = $TotalDirIgnored;
    'FileIgnored' = $TotalFileIgnored;
    'DirMismatched' = $TotalDirMismatched;
    'FileMismatched' = $TotalFileMismatched;
    'DirFailed' = $TotalDirFailed;
    'FileFailed' = $TotalFileFailed;
    'FailedDuration' = $FailedDuration
    'DirExtra' = $TotalDirExtra;
    'FileExtra' = $TotalFileExtra;
    'ExtraDuration' = $ExtraDuration
    'Speed' = (Format-SpeedHumanReadable $Speed) + '/s';
    'ExitCode' = $RoboRun.ExitCode;
    'Success' = $RoboRun.ExitCode -lt 8;
    'Message' = $Message
}

# Returns the result of the Robocopy command
New-Object -TypeName PSObject -Property $Property

# Cleans up Temp scan log file 
Remove-Item -Path $ScanLog

# Cleans up copy log file unless the $LogFile parameter has been used
if ($DisposeRoboLog) {
    Remove-Item -Path $RoboLog
}
