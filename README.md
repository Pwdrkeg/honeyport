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