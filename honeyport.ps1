<#
.SYNOPSIS
    Block IP Addresses that connect to a specified port.

.DESCRIPTION
    Creates a job that listens on TCP Ports specified and when 
    a connection is established, it can either simply log or
    add a local firewall rule to block the host from further
    connections.
    Writes blocked/probed IPs to the event log named HoneyPort.

.PARAMETER  Ports
    List of Ports to listen in for connections.

.PARAMETER  WhiteList
    List of IP Addresses that should not be blocked.

.EXAMPLE
    Example monitoring on different ports
        PS C:\> .\honeyport.ps1 -Ports 70,79 -Verbose

.EXAMPLE
    Example monitoring on different ports and add whitelist of hosts
        PS C:\> .\honeyport.ps1 -Ports 4444,22,21,23 -WhiteList 192.168.10.1,192.168.10.2 -Verbose

.EXAMPLE
    Example monitoring on one port and blocking on full TCP connect
        PS C:\> .\honeyport.ps1 -Ports 21 -Block

.NOTES
    Authors: John Hoyt, Carlos Perez
    Original Script Modified By: Greg Foss

    Stopping HoneyPort; 
        PS C:\> stop-job -name HoneyPort
        PS C:\> remove-job -name HoneyPort

    Listing Events;
        PS C:\> get-eventlog HoneyPort
#>
    
[CmdletBinding()]
param(
    [parameter(
    Mandatory = $true,
    ValueFromPipelineByPropertyName = $true,
    ValueFromPipeline = $true)]
    [Alias("PortNumber")]
    [int32[]]$Ports,

    [string[]]$WhiteList,

    [switch[]]$Block = $false
) 

function Check-IsAdmin{

     (whoami /all | Select-String S-1-16-12288) -ne $null
}

function Check-HoneyPortEvent
{
     if ((Get-WmiObject win32_NTEventlogfile -filter "filename='HoneyPort'") -ne $null){
         "HoneyPort Event-type has already been created!"
     } 
     else {
         new-eventlog -LogName HoneyPort -Source BlueKit
         "HoneyPort Event-type has been created!"
     }
}

function Get-SystemIPs
{
    $NonBlockIPs = @()
    # Select only those interfaces with an IP Addresses and are up
    Get-WmiObject Win32_NetworkAdapterConfiguration  -filter "IPEnabled=True" | 
        foreach-object {
            # Get the IPAdresses on the network interfaces
            foreach ($ipAddress in $_.IPAddress){
                $NonBlockIPs += $ipAddress
            }
            # Get DNS Server IPAddresses
            foreach ($DNSsrv in $_.DNSServerSearchOrder) {
                $NonBlockIPs += $DNSsrv
            }
            # Get IPAddressed from WINS and DHCP Servers
            $NonBlockIPs += $_.WINSPrimaryServer
            $NonBlockIPs += $_.WINSSecondaryServer
            $NonBlockIPs += $_.DHCPServer
        }
    # Retuns a de-duplicated list
    $NonBlockIPs | select -Unique
}


# Add IPAdresses the system depends on to the list.
$WhiteList+= Get-SystemIPs

Check-HoneyPortEvent

if (Check-IsAdmin) {
    foreach($port in $Ports) {
        $log = "HoneyPort has started listening for connections on port $port"        
	    write-eventlog -logname HoneyPort -source BlueKit -eventID 1001 -entrytype Information -message $log
        Write "Starting job that will listen for connections on port $port"
        Start-Job -ScriptBlock {
            param($port, $whitelist)
            # Create Objects needed.
            $endpoint = new-object System.Net.IPEndPoint([system.net.ipaddress]::any, $port)
            $listener = new-object System.Net.Sockets.TcpListener $endpoint
            # Run Listener
            while ($True){
                $listener.start()
                $client = $listener.AcceptTcpClient() 
                $IP = $client.Client.RemoteEndPoint
                $IP = $IP.tostring()
                $IP = $IP.split(':')
                $IP = $IP[0]

                # If the IP is not on the whitelist we block it
    
            if ($Block -eq $true) {
                if ($WhiteList -notcontains $IP){
                      write "The following host attempted to connect: $IP"
                      #Add firewall rule to block inbound scanner.
                      $firewall = New-Object -ComObject hnetcfg.fwpolicy2
                      $rule = New-Object -ComObject HNetCfg.FWRule
                      $rule.Name="Block scanner"
                      $rule.Description = "Blocking IP"
                      $rule.RemoteAddresses = $IP
                      $rule.Action = 0
                      #$rule.Direction = '1'
                      $rule.Protocol = 6
                      #$rule.RemotePorts = "*"
                      $rule.Enabled = $True
                      $firewall.Rules.Add($rule)
                      write "Host has been blocked."
		              $logIP = "$IP has been blocked on port $port"
		              write-eventlog -logname HoneyPort -source BlueKit -eventID 1002 -entrytype Information -message $logIP
                      $client.Close()
                      $listener.stop()	
                      Write "Connection closed"
                }
            } Else {
                $logIP = "$IP has probed the HoneyPort on port $port"
                write-eventlog -logname HoneyPort -source BlueKit -eventID 1002 -entrytype Information -message $logIP
                $client.Close()
                $listener.stop()	
                Write "Connection closed"
            }

            }
        } -ArgumentList $port,$WhiteList,$Block -Name "HoneyPort" -ErrorAction Stop
    }

    # Terminate Honeyport and Log Job Completion
    Write-Host "To terminate the HoneyPort, create the file $PSScriptRoot\stop.txt"

    # Wait for terminate 'command'

    while ($true) {
        start-sleep 60
        if (Test-Path "$PSScriptRoot\stop.txt") {
            stop-job HoneyPort
            remove-job HoneyPort
            $log = "HoneyPort has stopped listening for connections on all ports"
            Write-EventLog -LogName HoneyPort -source BlueKit -eventID 1003 -entrytype Information -message $log
            break
        }
    }
    
} else {
    Write-Error "Script needs to be run with higher privileges"
}
