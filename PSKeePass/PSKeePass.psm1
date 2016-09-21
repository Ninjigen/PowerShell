[String]$KeePassFolder="C:\Program Files (x86)\KeePass Password Safe 2"

Function Import-KeePass {
    <#
        .SYNOPSIS
            Loads all necessary KeePass assemblies
        .DESCRIPTION
            Loads all necessary KeePass assemblies from the KeePass installation folder
        .PARAMETER KeePassFolder
            KeePass installation folder (requires KeePass 2.x)
    #>
    Param(
        [Parameter(Mandatory=$False)]
        [String]$KeePassFolder=$KeePassFolder
    )
    Get-ChildItem -Recurse -Path $KeePassFolder | Where-Object {$_.Extension -match '^(.exe)|(.dll)$'} | Foreach-Object {
        $AssemblyName = $_.FullName
        try {
            [void]([Reflection.Assembly]::LoadFile($AssemblyName))
        } catch {
            Write-Verbose ("{0} could not be loaded" -f $AssemblyName)
        }
    }
}

Function Get-KeePass {
    <#
        .SYNOPSIS
            Retrieves all entries from a KeePass database file (.kdbx)
        .DESCRIPTION
            Retrieves all entries from a KeePass database file (.kdbx) using all available authentification methods (composite key, keyfile, windows account)
        .PARAMETER Database
            Path to the .kdbx keepass database file
        .PARAMETER Password
            Encrypted password to open the KeePass database
        .PARAMETER KeyFile
            Path to the .key keepass keyfile to open the KeePass database
        .PARAMETER Credential
            Credential used to open the KeePass database (only the password is taken into account)
        .PARAMETER UseWindowsAccount
            use the windows account to open the keepass database
        .PARAMETER UUID
            Filters with the UUID
        .PARAMETER GUID
            Filters with the UUID
        .PARAMETER UserName
            Filters with the UserName
        .PARAMETER Title
            Filters with the Title
        .EXAMPLE
            Get-KeePass -Database <Path to database>
            Asks for credentials to open the database
        .EXAMPLE
            Get-KeePass -Database <Path to database> -Password <[SecureString]>
        .EXAMPLE
            Get-KeePass -Database <Path to database> -KeyFile <Path to KeyFile>
        .EXAMPLE
            Get-KeePass -Database <Path to database> -UseWindowsAccount
        .EXAMPLE
            Get-KeePass -Database <Path to database> -Credential $Credential
        .EXAMPLE
            Get-KeePass -Database <Path to database> -Credential $Credential -KeyFile <Path to KeyFile>
        .EXAMPLE
            Get-KeePass -Database <Path to database> -Credential $Credential -KeyFile <Path to KeyFile> -UUID <UUID>
        .EXAMPLE
            Get-KeePass -Database <Path to database> -Credential $Credential -KeyFile <Path to KeyFile> -UserName <UserName> -Group <Group>
    #>
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Database,
        [Parameter(Mandatory=$False)]
        [SecureString]$Password,
        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]$Credential,        
        [Parameter(Mandatory=$False)]
        [String]$KeyFile,
        [switch]$UseWindowsAccount,
        [Parameter(Mandatory=$False)]
        [String]$UUID,
        [Parameter(Mandatory=$False)]
        [String]$Title,
        [Parameter(Mandatory=$False)]
        [String]$UserName,
        [Parameter(Mandatory=$False)]
        [String]$Group,
        [Parameter(Mandatory=$False)]
        [String]$GUID
    )
    $DatabaseItem = Get-Item $Database -ErrorAction Stop
    try {
        $DatabaseObject = New-Object KeepassLib.PwDatabase -ErrorAction Stop
    } catch {
        Import-KeePass -ErrorAction Stop
        $DatabaseObject = New-Object KeepassLib.PwDatabase
    }
    $CompositeKey = New-Object KeepassLib.Keys.CompositeKey
    if ($Credential.Password) {
        $CompositeKey.AddUserKey((New-Object KeepassLib.Keys.KcpPassword([System.Runtime.InteropServices.Marshal]::PtrToStringUni([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($credential.Password)))))
    }
    if ($Password) {
        $CompositeKey.AddUserKey((New-Object KeepassLib.Keys.KcpPassword([System.Runtime.InteropServices.Marshal]::PtrToStringUni([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)))))
    }
    if ($UseWindowsAccount) {
        $CompositeKey.AddUserKey((New-Object KeepassLib.Keys.KcpUserAccount))
    }
    if ((-not $Password) -and (-not $Credential.Password) -and (-not $KeyFile) -and (-not $UseWindowsAccount)) {
        $Credential = Get-Credential
    }
    if ($KeyFile) {
        try {
            $KeyFileItem = Get-Item $KeyFile -ErrorAction Stop
            Write-Verbose $KeyFileItem.FullName
            $CompositeKey.AddUserKey((New-Object KeepassLib.Keys.KcpKeyfile($KeyFileItem.FullName)))
        } catch {
            Write-Warning ("could not read Key file {0}" -f $KeyFileItem.FullName)
        }
    }

    $IOInfo = New-Object KeepassLib.Serialization.IOConnectionInfo
    $IOInfo.Path = $DatabaseItem.FullName

    $IStatusLogger = New-Object KeePassLib.Interfaces.NullStatusLogger

    $DatabaseObject.Open($IOInfo,$CompositeKey,$IStatusLogger)
    $DatabaseObject.RootGroup.getEntries($true) |Foreach-Object {
        $DatabaseEntry = $_
        $Property = [ordered]@{}
        [byte[]]$UUIDByte = $DatabaseEntry.UUID.UUIDBytes
        [byte[]]$GUIDByte = $DatabaseEntry.ParentGroup.UUID.UUIDBytes
        $Property.UUID = [System.BitConverter]::ToString($UUIDByte).Replace('-','')
        $Property.GUID = [System.BitConverter]::ToString($GUIDByte).Replace('-','')
        $Property.Group = $DatabaseEntry.ParentGroup.Name
        $Property.CreationTime = $DatabaseEntry.CreationTime
        $Property.LastModificationTime = $DatabaseEntry.LastModificationTime
        $Property.LastAccessTime = $DatabaseEntry.LastAccessTime
        $Property.ExpiryTime = $DatabaseEntry.ExpiryTime
        $Property.Expires = $DatabaseEntry.Expires
        $Property.UsageCount = $DatabaseEntry.UsageCount
        $Property.Tags = $DatabaseEntry.Tags
        $DatabaseEntry.Strings | Foreach-Object {
            [String]$key = $_.key
            if ($key -eq 'Password') {
                $Value = $DatabaseEntry.Strings.ReadSafe($key) | ConvertTo-SecureString -AsPlainText -Force
            } else {
                $Value = $DatabaseEntry.Strings.ReadSafe($key)
            }
            $Property."$key" = $Value
        }
        New-Object -TypeName PSCustomObject -Property $Property
    } | Where-Object {
        (($_.UUID -eq $UUID) -or (-not $UUID)) -and (($_.Title -eq $Title) -or (-not $Title)) -and (($_.UserName -eq $UserName) -or (-not $UserName)) -and (($_.GUID -eq $GUID) -or (-not $GUID))
    }
    $DatabaseObject.Close()
}

Function ConvertTo-PSCredential {
    <#
        .SYNOPSIS
            Converts a keepass entry into a PSCredential Object
        .DESCRIPTION
            Converts a keepass entry into a PSCredential Object
        .EXAMPLE
            Get-KeePass -Database <path do database> -UUID <UUID> | ConvertTo-PSCredential
    #>
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [Object[]]$Input
    )
    begin {

    }
    process {
        $Input | Foreach-Object {
            if (($_.UserName -like '*\*') -or (-not $_.Domain) -or (-not $_.ADDomain)) {
                $UserName = $_.UserName
                $Password = $_.Password
            } else {
                if ($_.Domain) {
                    $UserName = "{0}\{1}" -f $_.Domain.trim('\'),$_.UserName.trim('\')
                } else {
                    $UserName = "{0}\{1}" -f $_.ADDomain.trim('\'),$_.UserName.trim('\')
                }
            }
            New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($UserName, $Password)
        }
    }
    end {

    }
}