if (-not $KeePassFolder) {
    if ($env:KeePassFolder) {
        $KeePassFolder = $env:KeePassFolder
    } else {
        $KeePassFolder="C:\Program Files (x86)\KeePass Password Safe 2"
    }
}

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

Function New-KeePassDatabaseObject {
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Database,
        [Parameter(Mandatory=$False)]
        [SecureString]$Password,
        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]$Credential,        
        [Parameter(Mandatory=$False)]
        [String]$KeyFile,
        [switch]$UseWindowsAccount
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
            Write-Warning ("could not read Key file [{0}]" -f $KeyFileItem.FullName)
        }
    }

    $IOInfo = New-Object KeepassLib.Serialization.IOConnectionInfo
    $IOInfo.Path = $DatabaseItem.FullName

    $IStatusLogger = New-Object KeePassLib.Interfaces.NullStatusLogger

    $DatabaseObject.Open($IOInfo,$CompositeKey,$IStatusLogger) | Out-Null

    $DatabaseObject
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
    $NewDatabasePSBoundParameters = $PSBoundParameters
    if ($UUID) {$NewDatabasePSBoundParameters.remove('UUID') | Out-Null}
    if ($Title) {$NewDatabasePSBoundParameters.remove('Title') | Out-Null}
    if ($UserName) {$NewDatabasePSBoundParameters.remove('UserName') | Out-Null}
    if ($Group) {$NewDatabasePSBoundParameters.remove('Group') | Out-Null}
    if ($GUID) {$NewDatabasePSBoundParameters.remove('GUID') | Out-Null}
    $DatabaseObject = New-KeePassDatabaseObject @NewDatabasePSBoundParameters
    if (-not $DatabaseObject.IsOpen) {
        throw "InvalidDatabaseObjectException : could not open the database with provided parameters"
    }
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
        (($_.UUID -eq $UUID) -or (-not $UUID)) -and (($_.Title -eq $Title) -or (-not $Title)) -and (($_.UserName -eq $UserName) -or (-not $UserName)) -and (($_.GUID -eq $GUID) -or (-not $GUID)) -and (($_.Group -eq $Group) -or (-not $Group))
    }
    $DatabaseObject.Close() | Out-Null
}

Function Set-KeepassCompositeKey {
    <#
        .SYNOPSIS
            Changes the authentication method to access a keepass database
        .DESCRIPTION
            Changes the authentication method of a KeePass database file (.kdbx) using all available authentification methods (composite key, keyfile, windows account)
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
        .PARAMETER SetPassword
            Change the authentication method to use a password
        .PARAMETER SetKeyFile
            Change the authentication method to use a keyfile
        .PARAMETER SetCredential
            Change the authentication method to use a credential (only the password is used)
        .PARAMETER SetUseWindowsAccount
            Change the authentication method to use the current windows account
        .EXAMPLE
            Set-KeepassCompositeKey -Database $Database -Password <old password> -SetPassword <new password>
            Set-KeepassCompositeKey -Database $Database -Password <old password> -SetPassword <new password> -SetKeyfile <new keyfile>
            Set-KeepassCompositeKey -Database $Database -Password <old password> -SetPassword <new password> -SetKeyfile <new keyfile> -SetUseWindowsAccount
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
        [SecureString]$SetPassword,
        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]$SetCredential,        
        [Parameter(Mandatory=$False)]
        [String]$SetKeyFile,
        [switch]$SetUseWindowsAccount
    )
    $NewDatabasePSBoundParameters = $PSBoundParameters
    if ($SetPassword) {$NewDatabasePSBoundParameters.remove('SetPassword') | Out-Null}
    if ($SetCredential) {$NewDatabasePSBoundParameters.remove('SetCredential') | Out-Null}
    if ($SetKeyFile) {$NewDatabasePSBoundParameters.remove('SetKeyFile') | Out-Null}
    if ($SetUseWindowsAccount) {$NewDatabasePSBoundParameters.remove('SetUseWindowsAccount') | Out-Null}
    $DatabaseObject = New-KeePassDatabaseObject @NewDatabasePSBoundParameters
    if (-not $DatabaseObject.IsOpen) {
        throw "InvalidDatabaseObjectException : could not open the database with provided parameters"
    }

    $SetCompositeKey = New-Object KeepassLib.Keys.CompositeKey
    if ($SetCredential.Password) {
        $SetCompositeKey.AddUserKey((New-Object KeepassLib.Keys.KcpPassword([System.Runtime.InteropServices.Marshal]::PtrToStringUni([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Setcredential.Password)))))
    }
    if ($SetPassword) {
        $SetCompositeKey.AddUserKey((New-Object KeepassLib.Keys.KcpPassword([System.Runtime.InteropServices.Marshal]::PtrToStringUni([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SetPassword)))))
    }
    if ($SetUseWindowsAccount) {
        $SetCompositeKey.AddUserKey((New-Object KeepassLib.Keys.KcpUserAccount))
    }
    if ($SetKeyFile) {
        try {
            $SetKeyFileItem = Get-Item $SetKeyFile -ErrorAction Stop
            $SetCompositeKey.AddUserKey((New-Object KeepassLib.Keys.KcpKeyfile($SetKeyFileItem.FullName)))
        } catch {
            Write-Warning ("could not read Key file [{0}]" -f $SetKeyFileItem.FullName)
        }
    }
    if ((-not $SetPassword) -and (-not $SetCredential.Password) -and (-not $SetKeyFile) -and (-not $SetUseWindowsAccount)) {
        throw "InvalidInputException : Cannot create composite key with this information"
    }

    $DatabaseObject.MasterKey = $SetCompositeKey

    $IStatusLogger = New-Object KeePassLib.Interfaces.NullStatusLogger

    $DatabaseObject.Save($IStatusLogger)

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
            if (($_.UserName -like '*\*') -or ((-not $_.Domain) -and (-not $_.ADDomain))) {
                $UserName = $_.UserName
            } else {
                if ($_.Domain) {
                    $UserName = "{0}\{1}" -f $_.Domain.trim('\'),$_.UserName.trim('\')
                } elseif ($_.ADDomain) {
                    $UserName = "{0}\{1}" -f $_.ADDomain.trim('\'),$_.UserName.trim('\')
                }
            }
            $Password = $_.Password
            New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($UserName, $Password)
        }
    }
    end {

    }
}

Function Add-KeepassEntry {
    <#
        .SYNOPSIS
            Adds an entry to a KeePass database file (.kdbx)
        .DESCRIPTION
            Adds an entry to a KeePass database file (.kdbx) using all available authentification methods (composite key, keyfile, windows account)
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
        .PARAMETER Property
            Dictionary of all custom properties to add
        .PARAMETER Title
            Title of the entry
        .PARAMETER EntryCredential
            Credential used to create the entry
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
        [Hashtable]$Property,
        [Parameter(Mandatory=$True)]
        [String]$Title,
        [Parameter(Mandatory=$True)]
        [System.Management.Automation.PSCredential]$EntryCredential
    )
    $NewDatabasePSBoundParameters = $PSBoundParameters
    if ($Property) {$NewDatabasePSBoundParameters.remove('Property') | Out-Null}
    if ($Title) {$NewDatabasePSBoundParameters.remove('Title') | Out-Null}
    if ($EntryCredential) {$NewDatabasePSBoundParameters.remove('EntryCredential') | Out-Null}
    $DatabaseObject = New-KeePassDatabaseObject @NewDatabasePSBoundParameters
    if (-not $DatabaseObject.IsOpen) {
        throw "InvalidDatabaseObjectException : could not open the database with provided parameters"
    }

    $EntryObject = New-Object -TypeName KeepassLib.PWEntry -ArgumentList ($true,$true)
    [byte[]]$EntryObjectUUIDByte = $EntryObject.UUID.UUIDBytes
    $EntryObjectUUID = [System.BitConverter]::ToString($EntryObjectUUIDByte).Replace('-','')
    $ProtectedUserName = New-Object -TypeName KeepassLib.Security.ProtectedString -ArgumentList ($true,[string]($EntryCredential.UserName))
    $EntryObject.Strings.Set("UserName",$ProtectedUserName)
    $EntryObject.Strings.Set("Password",(New-Object KeepassLib.Security.ProtectedString -ArgumentList ($true,([System.Runtime.InteropServices.Marshal]::PtrToStringUni([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($EntryCredential.Password))))))
    $ProtectedNotes = New-Object -TypeName KeepassLib.Security.ProtectedString -ArgumentList ($true,"")
    $EntryObject.Strings.Set("Notes",$ProtectedNotes)
    $ProtectedTitle = New-Object -TypeName KeepassLib.Security.ProtectedString -ArgumentList ($true,[string]($Title))
    $EntryObject.Strings.Set("Title",$ProtectedTitle)
    if ($Property) {
        $Property.keys | Foreach-Object {
            $key = $_
            $Value = New-Object -TypeName KeepassLib.Security.ProtectedString -ArgumentList ($true,[string]($Property."$key"))
            $EntryObject.Strings.Set($key,$Value)
        }
    }

    $DatabaseObject.RootGroup.addEntry($EntryObject,$false)

    $IStatusLogger = New-Object KeePassLib.Interfaces.NullStatusLogger

    $DatabaseObject.Save($IStatusLogger)

    $DatabaseObject.Close()

    $NewDatabasePSBoundParameters.UUID = $EntryObjectUUID

    Get-KeePass @NewDatabasePSBoundParameters
}

Function Remove-KeepassEntry {
    <#
        .SYNOPSIS
            Removes an entry from a KeePass database file (.kdbx)
        .DESCRIPTION
            Removes an entry from a KeePass database file (.kdbx) using all available authentification methods (composite key, keyfile, windows account)
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
            UUID of the entry to remove
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
        [Parameter(Mandatory=$True)]
        [String]$UUID
    )
    $NewDatabasePSBoundParameters = $PSBoundParameters
    if ($UUID) {$NewDatabasePSBoundParameters.remove('UUID') | Out-Null}
    $DatabaseObject = New-KeePassDatabaseObject @NewDatabasePSBoundParameters
    if (-not $DatabaseObject.IsOpen) {
        throw "InvalidDatabaseObjectException : could not open the database with provided parameters"
    }
    $DatabaseEntry,$trash = $DatabaseObject.RootGroup.Entries | Where-Object {
        [Byte[]]$UUIDByte = $_.UUID.UUIDBytes
        [System.BitConverter]::ToString($UUIDByte).Replace('-','') -eq $UUID
    }
    if ($DatabaseEntry) {
        if (-not ($DatabaseObject.RootGroup.Entries.Remove($DatabaseEntry))) {
            throw ("InvalidOperationException : could not remove entry [{0}]" -f $UUID)
        }
    } else {
        throw ("EntryNotFoundException : entry with UUID [{0}] does not exist" -f $UUID)
    }
    $IStatusLogger = New-Object KeePassLib.Interfaces.NullStatusLogger

    $DatabaseObject.Save($IStatusLogger)
    $DatabaseObject.Close()
}

Function Edit-KeepassEntry {
    <#
        .SYNOPSIS
            Edits an entry from a KeePass database file (.kdbx)
        .DESCRIPTION
            Edits an entry from a KeePass database file (.kdbx) using all available authentification methods (composite key, keyfile, windows account)
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
            UUID of the entry
        .PARAMETER NewCredential
            Credential used to create the entry
        .PARAMETER Property
            Dictionary of all custom properties to add
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
        [Parameter(Mandatory=$True)]
        [String]$UUID,
        [Parameter(Mandatory=$True)]
        [System.Management.Automation.PSCredential]$NewCredential,
        [Parameter(Mandatory=$False)]
        [Hashtable]$Property
    )
    $NewDatabasePSBoundParameters = $PSBoundParameters
    if ($UUID) {$NewDatabasePSBoundParameters.remove('UUID') | Out-Null}
    if ($NewCredential) {$NewDatabasePSBoundParameters.remove('NewCredential') | Out-Null}
    if ($Property) {$NewDatabasePSBoundParameters.remove('Property') | Out-Null}
    $DatabaseObject = New-KeePassDatabaseObject @NewDatabasePSBoundParameters
    if (-not $DatabaseObject.IsOpen) {
        throw "InvalidDatabaseObjectException : could not open the database with provided parameters"
    }
    $EntryObject,$trash = $DatabaseObject.RootGroup.Entries | Where-Object {
        [Byte[]]$UUIDByte = $_.UUID.UUIDBytes
        [System.BitConverter]::ToString($UUIDByte).Replace('-','') -eq $UUID
    }
    if ($EntryObject) {
        if ($NewCredential) {
            $ProtectedUserName = New-Object -TypeName KeepassLib.Security.ProtectedString -ArgumentList ($true,[string]($NewCredential.UserName))
            $EntryObject.Strings.Set("UserName",$ProtectedUserName)
            $ProtectedPassword = New-Object -TypeName KeepassLib.Security.ProtectedString -ArgumentList ($true,[string]([System.Runtime.InteropServices.Marshal]::PtrToStringUni([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($NewCredential.Password))))
            $EntryObject.Strings.Set("Password",$ProtectedPassword)
        }
        if ($Property) {
            $Property.keys | Foreach-Object {
                $key = $_
                $Value = New-Object -TypeName KeepassLib.Security.ProtectedString -ArgumentList ($true,[string]($Property.$key))
                $EntryObject.Strings.Set($key,$Value)
            }
        }
    } else {
        throw ("EntryNotFoundException : entry with UUID [{0}] does not exist" -f $UUID)
    }

    $IStatusLogger = New-Object KeePassLib.Interfaces.NullStatusLogger

    $DatabaseObject.Save($IStatusLogger)
    $DatabaseObject.Close()

    $NewDatabasePSBoundParameters.UUID = $UUID

    Get-KeePass @NewDatabasePSBoundParameters
}

Export-ModuleMember -Variable "KeePassFolder"

Export-ModuleMember -Function "Import-KeePass"
Export-ModuleMember -Function "Get-KeePass"
Export-ModuleMember -Function "Set-KeepassCompositeKey"
Export-ModuleMember -Function "ConvertTo-PSCredential"
Export-ModuleMember -Function "Add-KeepassEntry"
Export-ModuleMember -Function "Edit-KeepassEntry"
Export-ModuleMember -Function "Remove-KeepassEntry"