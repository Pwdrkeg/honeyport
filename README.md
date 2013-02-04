<#
.Synopsis
	Block IP Addresses that connect to a specified port.

.DESCRIPTION
	Creates a job that listens on TCP Ports specified and when a connection is established, it adds a local firewall rule to block the host from further connections.  Writes blocked IPs to the event log named HoneyPort.

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

.NOTES
	Authors: John Hoyt, Carlos Perez
	
	Stopping HoneyPort; 
		stop-job -name HoneyPort
		remove-job -name HoneyPort
	
	Listing Events;
	get-eventlog HoneyPort
	
#>
