.SYNOPSIS
    Block IP Addresses that connect to specified TCP ports.

.DESCRIPTION
    Listens on TCP ports, logging connections and optionally blocking suspicious IPs via Windows Firewall.
    Includes detailed logging, proper firewall rule creation verification, and improved error handling.

.PARAMETER Ports
    List of TCP ports to monitor for connections.

.PARAMETER WhiteList
    List of IP Addresses that should not be blocked.

.PARAMETER Block
    If specified, blocks the connecting IP addresses.

.PARAMETER LogPath
    Optional path for logs. Defaults to "C:\HoneyPort_Logs".

.EXAMPLE
    PS C:\> .\honeyport.ps1 -Ports 22,23,1001 -Block -Verbose
