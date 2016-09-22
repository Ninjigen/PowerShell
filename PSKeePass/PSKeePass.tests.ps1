Import-Module PSKeePass -Force

$InvocationItem = Get-Item $MyInvocation.MyCommand.Path

Describe "Import-Keepass" {
    It "should work" {
        { 
            Import-Keepass -ErrorAction Stop
            New-Object KeePassLib.PwDatabase -ErrorAction Stop
        } | Should not throw

    }
}

$PasswordProtectedDatabase = Join-Path $InvocationItem.Directory.FullName "tests\Password.kdbx"
$KeyFileProtectedDatabase = Join-Path $InvocationItem.Directory.FullName "tests\KeyFile.kdbx"
$KeyFile = Join-Path $InvocationItem.Directory.FullName "tests\KeyFile.key"
$WrongKeyFile = Join-Path $InvocationItem.Directory.FullName "tests\WrongKeyFile.key"
$PlainPassword = "toto"
$WrongPlainPassword = "wrongtoto"
$Password = $PlainPassword | ConvertTo-SecureString -AsPlainText -Force
$WrongPassword = $WrongPlainPassword | ConvertTo-SecureString -AsPlainText -Force
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ("toto", $Password)
$WrongCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ("toto", $WrongPassword)

Describe "Get-KeePass" {
    It "opens a password-protected keepass with the correct password" {
        Get-KeePass -Database $PasswordProtectedDatabase -Password $Password | Should not be $null
    }
    It "opens a password-protected keepass with the correct Credential" {
        Get-KeePass -Database $PasswordProtectedDatabase -Credential $Credential | Should not be $null
    }
    It "opens a keyfile-protected keepass with the correct file" {
        Get-KeePass -Database $KeyfileProtectedDatabase -KeyFile $KeyFile | Should not be $null
    }
    It "doesn't open a password-protected keepass with the wrong password" {
        {Get-KeePass -Database $PasswordProtectedDatabase -Password $WrongPassword} | Should throw
    }
    It "doesn't open a password-protected keepass with the wrong credential" {
        {Get-KeePass -Database $PasswordProtectedDatabase -Credential $WrongCredential} | Should throw
    }
    It "doesn't open a password-protected keepass with the wrong keyfile" {
        {Get-KeePass -Database $PasswordProtectedDatabase -KeyFile $WrongKeyFile} | Should throw
    }
    It "filters by UUID" {
        $KeepassRootEntry1 = Get-KeePass -Database $KeyfileProtectedDatabase -KeyFile $KeyFile -UUID "DCED00B817989843A55C2F9B518651DB"
        $KeepassRootEntry1.UserName | Should be "rootentry1"
        $KeepassRootEntry1.Title | Should be "RootEntry1"
        [System.Runtime.InteropServices.Marshal]::PtrToStringUni([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($KeepassRootEntry1.Password)) | Should be "rootentry1"
    }
    It "filters by UserName" {
        $KeepassRootEntry1 = Get-KeePass -Database $KeyfileProtectedDatabase -KeyFile $KeyFile -UserName "rootentry1"
        $KeepassRootEntry1.UUID | Should be "DCED00B817989843A55C2F9B518651DB"
        $KeepassRootEntry1.Title | Should be "RootEntry1"
        [System.Runtime.InteropServices.Marshal]::PtrToStringUni([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($KeepassRootEntry1.Password)) | Should be "rootentry1"
    }
    It "filters by Title" {
        $KeepassRootEntry1 = Get-KeePass -Database $KeyfileProtectedDatabase -KeyFile $KeyFile -Title "RootEntry1"
        $KeepassRootEntry1.UUID | Should be "DCED00B817989843A55C2F9B518651DB"
        $KeepassRootEntry1.username | Should be "rootentry1"
        [System.Runtime.InteropServices.Marshal]::PtrToStringUni([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($KeepassRootEntry1.Password)) | Should be "rootentry1"
    }
    It "filters by Group" {
        $KeepassEntries = Get-KeePass -Database $KeyfileProtectedDatabase -KeyFile $KeyFile -Group Windows
        $KeepassEntries.count | Should be 2
    }
    It "uses secured strings as password" {
        Get-KeePass -Database $KeyfileProtectedDatabase -KeyFile $KeyFile | Foreach-Object {
            $_.Password.GetType().Name | Should be "SecureString"
        }
    }
    It "finds custom properties" {
        $RootEntry3 = Get-KeePass -Database $KeyFileProtectedDatabase -KeyFile $KeyFile -UUID "60F6F2F1FA883D4E9E04D85BBFC8B05A"
        $RootEntry3.key1 | Should be "Value1"
        $RootEntry3.key2 | Should be "Value2"
        $RootEntry3.key3 | Should be "Value3"
    }
}


Describe "ConvertTo-PSCredential" {
    $KeePassCredentialWithoutDomain = Get-KeePass -Database $KeyfileProtectedDatabase -KeyFile $KeyFile -UUID "DCED00B817989843A55C2F9B518651DB" | ConvertTo-PSCredential
    $KeePassCredentialWithDomain = Get-KeePass -Database $KeyfileProtectedDatabase -KeyFile $KeyFile -UUID "0010E346EEE7504FB7B5B6A6302A3A26" | ConvertTo-PSCredential
    $KeePassCredentialWithDomainAsProperty = Get-KeePass -Database $KeyfileProtectedDatabase -KeyFile $KeyFile -UUID "7D6E0EEE3EAE7240A3D9252D823ABA72" | ConvertTo-PSCredential
    It "returns PSCredentials" {
        $KeePassCredentialWithoutDomain.GetType().Name | Should be "PSCredential"
    }
    It "gets the correct user" {
        $KeePassCredentialWithoutDomain.UserName | Should be "rootentry1"
        $KeePassCredentialWithDomain.UserName | Should be "WindowsDomain\WindowsUser2"
        $KeePassCredentialWithDomainAsProperty.UserName | Should be "WindowsDomain\WindowsUser1"
    }
}