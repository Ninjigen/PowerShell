# PSKeePass
## Introduction
This is a module to access a Keepass database (http://keepass.info/)
## Installation
Requires at least PowerShell V3.0 (tested on PowerShell V5.x)
Clone the repository somewhere on your computer, then add the path to the *$env:PSModulePath* variable.
Alternatively, you can put it under the WindowsPowerShell\Modules folder in your My Documents folder (you might need to create it), as it is the default PowerShell module path, so that the PSKeePass folder is located here : 
*...MyDOcuments\WindowsPowerShell\Modules\PSKeepass*

Edit the $KeePassFolder variable in the KeePass.psm1 module to the path leading to your KeePass installation

## TroubleShooting
If you're having issues running the module, please send the output of the Invoke-Pester command ran in the PSKeepass Folder.
I can provide support in french and english, and to some extend in spanish and japaneese (I'd be heavily google-translating though)
## Contributions
Thanks to the #FRPSUG community for their feedback and support.
## Disclaimer
I do not own any license attached to Keepass nor do I have any link to Dominik Reichl or any other contributor to the KeePass project
