honeyport
=========


honeyport is a network defense tool written in Powershell 2.0.  It opens up a specific tcp port on the local host,
and when a connection is established it adds a local firewall rule to block the offending IP.  

The idea is based off of the PaulDotCom Security Podcast episode 203 and the command line script written by
John Strand and Mick Douglas.

Usage:  It can be run manually from the Windows PowerShell command line or from Run, but I've found that it works best 
to run it from the Windows Task Scheduler.  It does require administrative priveledges to add the firewall rule.
The only argument required is the port number you choose.

- From the PowerShell Command Line (with Administrator Priveledges)
  - honeyport.ps1 3333 

- From Run (with Administrator Priveledges) 
  - powershell.exe honeyport.ps1 3333

- From Task Scheduler 
  - Create a new Task (On the General Tab be sure to check "Run with highest privileges"
  - On the Actions Tab select New:
  - Program / script, browse out to select the PowerShell executable
    - "c:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
  - Add arguments
    - "-windowstyle hidden -Command "&c:\scripts\honeyport.ps1 3333"