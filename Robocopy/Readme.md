# Introduction

This is a powershell script that creates a separate process to use robocopy, then parses a temp log in order to display a progress bar with little to no overhead time. As far as my google skills have taken me, I haven't found a faster way to copy files over the network than Robocopy. It is usually installed by default on any windows OS that is still supported by Microsoft.

This is a linted/rewritten version of Keith S. Garner (KeithGa@KeithGa.com) script.
He explains in details how the script works in his blog post over here : https://keithga.wordpress.com/2014/06/23/copy-itemwithprogress

Also credits to Trevor Sullivan who had the original idea, as posted in this stackoverflow thread : https://stackoverflow.com/questions/13883404/custom-robocopy-progress-bar-in-powershell

His module is demonstrated in the following Youtube video : http://www.youtube.com/watch?v=z9KeYa842rc

# Disclaimer

This script hasn't been extensively tested on any windows OS (Mainly on Windows 7/2008 R2). There are known issues with different versions of robocopy (in particular due to encoding/culture issues).

# Example

**C:\PS> .\Start-Robocopy -Source "c:\Src" -Destination "d:\Dest" [-Files 'file1.ext1' '*.ext2'] [-RobocopyArgs "/IS" "/IT"]**

* Copy the contents of the c:\Src directory to a directory d:\Dest
* Without the /e or /mir switch, only files from the root of c:\src are copied.
* See https://technet.microsoft.com/en-us/library/cc733145(v=ws.11).aspx for an extensive documentation on Robocopy switches
* The following switches MUST not be used : 
  * /NDL
  * /TEE
  * /bytes
  * /LOG:LOGFILE (please use the **-LogFile** parameter instead)
  * /NFL
  * /L
  * /NC 

# Licence and support

This script has been posted here for future reference, and if people struggle like I did with writing a Robocopy function for PowerShell. It has been posted without notice of the aforementioned persons.
