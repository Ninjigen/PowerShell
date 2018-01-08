This is a powershell script that creates a separate process to use robocopy, then parses a temp log in order to display a progress bar with little to no overhead time.

This is a linted/rewritten version of Keith S. Garner (KeithGa@KeithGa.com) script.
He explains in details how the script works in his blog post over here : https://keithga.wordpress.com/2014/06/23/copy-itemwithprogress

Example : 

C:\PS> .\Start-Robocopy -Source "c:\Src" -Destination "d:\Dest" [-Files 'file1.ext1' '*.ext2'] [-RobocopyArgs "/IS" "/IT"]

Copy the contents of the c:\Src directory to a directory d:\Dest
Without the /e or /mir switch, only files from the root of c:\src are copied.
See https://technet.microsoft.com/en-us/library/cc733145(v=ws.11).aspx for an extensive documentation on Robocopy switches
The following switches MUST not be used : 
    - /NDL
    - /TEE
    - /bytes
    - /LOG:<logfile>
    - /NFL
    - /L
    - /NC 
