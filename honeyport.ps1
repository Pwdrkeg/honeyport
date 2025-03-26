<#
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
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
    [Alias("PortNumber")]
    [int32[]]$Ports,

    [string[]]$WhiteList = @(),

    [switch]$Block,
    
    [string]$LogPath = "C:\HoneyPort_Logs"
)

function Show-BlueShellAsciiArt {
    Write-Host "`n"
    Write-Host "                             .:                             "
    Write-Host "                           ....:                            "
    Write-Host "                          :....:--                          "
    Write-Host "                          ::..::--                          "
    Write-Host "                         -:::::--==                         "
    Write-Host "                        ======+++++*                        "
    Write-Host "       :.:::::      *#######****#####****                   "
    Write-Host "       ::..::::--+****####%%*=++***#######*    ::           "
    Write-Host "       -:::.::::--=+******##@##**########%%#=:::-           "
    Write-Host "        -:::::::---=*******%@#*********##%####*-=           "
    Write-Host "        ----------=***++++*%%*++++++=====+++####*+          "
    Write-Host "         ==-----=+++++++=+*%#+=++-::.....:-*=###-:::.......:  "
    Write-Host "    ....-++===+**+++====-=#%+===-:::..::-==*#+##=:......::==  "
    Write-Host "    :::-+******+++===--=*%%%=--=--:::::-===##**#*-:::::-==    "
    Write-Host "      -++++****++==--+##+-=#*--===-----===+#%#+#**=-==+=      "
    Write-Host "    ............--=#%#+=---*%=-==++==++++*#%%%**####*+=       "
    Write-Host " .....................:=#**+%*====++++**######%******#=-      "
    Write-Host "...........................:=+**+++++++******##########+==    "
    Write-Host ":::::::.........................:=###*******##+**#####*::-=   "
    Write-Host ":::------::::........................:-=+*##%**###%#+-:::::-  "
    Write-Host "--===++=*%@#==-::::.........................::::::::::::::--  "
    Write-Host " =======*@@@@@@*==---:::::...................::::::::::::--=  "
    Write-Host "   ==-.:*@@@@@@=::=+*+===--:::::::::........:::::::::::--===   "
    Write-Host "     :..-%@@@@%:..:-++=#@%#*+===-----::::::::::::::---===-    "
    Write-Host "      :::=%@@@=..::-=--#@@@@@@@%#+====================--      "
    Write-Host "      ::::---::::-===::+@@@@@@@@@@*-==============---         "
    Write-Host "       -:::::::-==++::::-#@@@@@@%+================-           "
    Write-Host "          ---====+=-:::::::------================-            "
    Write-Host "            -=====---::---=-:-----=============--             "
    Write-Host "              ============--================---               "
    Write-Host "                 =======================----                  "
    Write-Host "                     =-=============----                      "
    
    Write-Host "`n  ╔══════════════════════════════════════════╗"
    Write-Host "  ║  HoneyPort TCP Listener & IP Blocker     ║"
    Write-Host "  ║  Coming for unauthorized connections...  ║"
    Write-Host "  ╚══════════════════════════════════════════╝`n"
}

# Create log directory if it doesn't exist
if (!(Test-Path -Path $LogPath)) {
    New-Item -ItemType Directory -Force -Path $LogPath | Out-Null
    Write-Verbose "Created log directory: $LogPath"
}

$ActivityLogFile = Join-Path -Path $LogPath -ChildPath "HoneyPort_Activity.log"
$FirewallLogFile = Join-Path -Path $LogPath -ChildPath "HoneyPort_Firewall.log"

# Creating empty log files if they don't exist
if (!(Test-Path -Path $ActivityLogFile)) {
    New-Item -ItemType File -Force -Path $ActivityLogFile | Out-Null
}
if (!(Test-Path -Path $FirewallLogFile)) {
    New-Item -ItemType File -Force -Path $FirewallLogFile | Out-Null
}

function Write-CustomLog {
    param(
        [string]$Message,
        [string]$LogFile,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp [$Level] $Message" | Out-File -Append -FilePath $LogFile
    
    if ($Level -eq "ERROR") {
        Write-Error $Message
    } elseif ($VerbosePreference -eq 'Continue' -or $Level -eq "WARNING") {
        Write-Verbose $Message
    }
}

function Test-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Initialize-EventLog {
    try {
        # Check if the event log exists
        $eventLogExists = [System.Diagnostics.EventLog]::Exists("HoneyPort")
        
        if (-not $eventLogExists) {
            try {
                # Create the new event log
                New-EventLog -LogName HoneyPort -Source BlueKit | Out-Null
                Write-CustomLog -Message "HoneyPort event log created successfully." -LogFile $ActivityLogFile
            } catch {
                # If New-EventLog fails, attempt an alternative method
                try {
                    # Using WMI to create the event log
                    $logCreation = @"
                    $ErrorActionPreference = 'Stop'
                    $log = New-Object System.Diagnostics.Diagnostics.EventLog("HoneyPort")
                    $log.Source = "BlueKit"
"@
                    powershell.exe -Command $logCreation
                    Write-CustomLog -Message "HoneyPort event log created using alternative method." -LogFile $ActivityLogFile
                } catch {
                    # Log the error but don't stop script execution
                    Write-CustomLog -Message "Failed to create HoneyPort event log: $_" -LogFile $ActivityLogFile -Level "ERROR"
                    Write-Warning "Could not create HoneyPort event log. Logging to Windows Event Log will be skipped."
                }
            }
        } else {
            Write-CustomLog -Message "HoneyPort event log already exists." -LogFile $ActivityLogFile
        }
    } catch {
        Write-CustomLog -Message "Error checking HoneyPort event log existence: $_" -LogFile $ActivityLogFile -Level "ERROR"
        Write-Warning "Unable to verify or create HoneyPort event log."
    }
}

function Get-SystemIPs {
    try {
        $systemIPs = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" | 
            ForEach-Object { 
                $_.IPAddress + $_.DNSServerSearchOrder + $_.WINSPrimaryServer + 
                $_.WINSSecondaryServer + $_.DHCPServer 
            } | 
            Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } | 
            Select-Object -Unique
        
        # Always include localhost
        $systemIPs += @("127.0.0.1", "::1")
        
        return $systemIPs
    } catch {
        Write-Error "Error collecting system IPs: $_"
        return @("127.0.0.1", "::1")  # Return at least localhost if we fail
    }
}

# Test if Windows Firewall is properly accessible
function Test-FirewallAccess {
    try {
        # Try to list firewall rules to ensure we have access
        $testRules = Get-NetFirewallRule -ErrorAction Stop | Select-Object -First 1
        Write-CustomLog -Message "Firewall access verified successfully." -LogFile $FirewallLogFile
        return $true
    } catch {
        Write-Error "Firewall access test failed: $_"
        Write-Error "Make sure Windows Firewall service is running and you have admin rights."
        return $false
    }
}

# Display the cool ASCII art
Show-BlueShellAsciiArt

# Main script execution
Write-CustomLog -Message "HoneyPort script started. Version 1.2" -LogFile $ActivityLogFile

# Check admin privileges
if (-not (Test-Admin)) {
    throw "This script requires Administrator privileges. Please restart as Administrator."
}

# Test firewall access
$firewallAccessible = Test-FirewallAccess
if (-not $firewallAccessible) {
    Write-Host "WARNING: Windows Firewall appears to be inaccessible. Blocking functionality may not work." -ForegroundColor Yellow
}

# Initialize Event Log
Initialize-EventLog

# Add system IPs to whitelist
$systemIPs = Get-SystemIPs
$WhiteList += $systemIPs
$WhiteList = $WhiteList | Select-Object -Unique

Write-CustomLog -Message "Whitelist configured with $($WhiteList.Count) IPs" -LogFile $ActivityLogFile

# Start a listener job for each port
foreach ($port in $Ports) {
    Write-CustomLog -Message "Starting job for port $port" -LogFile $ActivityLogFile
    
    Start-Job -Name "HoneyPort_$port" -ScriptBlock {
        param($Port, $WhiteList, $Block, $ActivityLog, $FirewallLog)
        
        # Define all functions directly within the job scope
        function Write-CustomLog {
            param(
                [string]$Message,
                [string]$LogFile,
                [string]$Level = "INFO"
            )
            
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            "$timestamp [$Level] $Message" | Out-File -Append -FilePath $LogFile
            
            if ($Level -eq "ERROR") {
                Write-Error $Message
            } elseif ($VerbosePreference -eq 'Continue' -or $Level -eq "WARNING") {
                Write-Verbose $Message
            }
        }
        
        function New-HoneyPortFirewallRule {
            param(
                [string]$IP,
                [int]$Port
            )
            
            $ruleName = "HoneyPort_Block_$IP"
            Write-CustomLog -Message "Creating firewall rule: $ruleName" -LogFile $FirewallLog
            
            try {
                # Check if rule already exists
                $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
                
                if ($existingRule) {
                    Write-CustomLog -Message "Firewall rule for $IP already exists. Rule ID: $($existingRule.Name)" -LogFile $FirewallLog
                    return $true
                }
                
                # Create the rule with specific parameters - Use full cmdlet name and capture output
                $newRule = New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Block -RemoteAddress $IP -Protocol TCP -Enabled True -Description "Created by HoneyPort script on $(Get-Date) for port $Port" -ErrorAction Stop
                
                # Log rule details
                Write-CustomLog -Message "Rule created: $ruleName" -LogFile $FirewallLog
                
                # Verify rule exists now
                Start-Sleep -Seconds 2
                $verifyRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
                
                if ($verifyRule) {
                    Write-CustomLog -Message "Successfully verified creation of firewall rule: $ruleName" -LogFile $FirewallLog
                    return $true
                } else {
                    Write-CustomLog -Message "Failed to verify firewall rule creation for $IP" -LogFile $FirewallLog -Level "ERROR"
                    
                    # Try an alternate method to check
                    $altCheck = Get-NetFirewallRule | Where-Object { $_.DisplayName -like "*$IP*" }
                    if ($altCheck) {
                        Write-CustomLog -Message "Alternative check: Found rule with IP in name: $($altCheck.DisplayName)" -LogFile $FirewallLog
                        return $true
                    }
                    
                    return $false
                }
            } catch {
                Write-CustomLog -Message "Error creating firewall rule for $IP`: $_" -LogFile $FirewallLog -Level "ERROR"
                
                # Try direct command to see if it works via cmd
                try {
                    $cmdOutput = & netsh advfirewall firewall add rule name="HoneyPort_Block_$IP" dir=in action=block remoteip=$IP
                    Write-CustomLog -Message "Fallback method (netsh) output: $cmdOutput" -LogFile $FirewallLog
                    
                    # Check if rule was created with netsh
                    $netshCheck = Get-NetFirewallRule | Where-Object { $_.DisplayName -eq "HoneyPort_Block_$IP" }
                    if ($netshCheck) {
                        Write-CustomLog -Message "Fallback method successful: Rule created via netsh" -LogFile $FirewallLog
                        return $true
                    } else {
                        Write-CustomLog -Message "Fallback method failed: Rule not created via netsh" -LogFile $FirewallLog -Level "ERROR"
                    }
                } catch {
                    Write-CustomLog -Message "Fallback method error: $_" -LogFile $FirewallLog -Level "ERROR"
                }
                
                return $false
            }
        }
        
        function Start-HoneyPortListener {
            param(
                [int]$Port,
                [string[]]$WhiteList,
                [bool]$ShouldBlock,
                [string]$ActivityLog,
                [string]$FirewallLog
            )
            
            Write-CustomLog -Message "Starting listener on port $Port" -LogFile $ActivityLog
            
            try {
                $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any, $Port)
                $listener.Start()
                
                Write-CustomLog -Message "Listener successfully started on port $Port" -LogFile $ActivityLog
                
                while ($true) {
                    try {
                        if ($listener.Pending()) {
                            $client = $listener.AcceptTcpClient()
                            $IP = $client.Client.RemoteEndPoint.Address.ToString()
                            
                            Write-CustomLog -Message "Connection detected from $IP on port $Port" -LogFile $ActivityLog
                            
                            if ($WhiteList -notcontains $IP) {
                                # Log to Windows Event Log
                                try {
                                    Write-EventLog -LogName HoneyPort -Source BlueKit -EventId 1002 -EntryType Information -Message "Connection from $IP detected on port $Port at $(Get-Date)"
                                } catch {
                                    Write-Error "Failed to write to Event Log: $_"
                                }
                                
                                if ($ShouldBlock) {
                                    Write-CustomLog -Message "Attempting to block IP: $IP on port $Port" -LogFile $ActivityLog
                                    
                                    $ruleCreated = New-HoneyPortFirewallRule -IP $IP -Port $Port
                                    
                                    if ($ruleCreated) {
                                        Write-CustomLog -Message "Successfully blocked IP $IP" -LogFile $ActivityLog
                                    } else {
                                        Write-CustomLog -Message "Failed to block IP $IP" -LogFile $FirewallLog -Level "ERROR"
                                    }
                                }
                            } else {
                                Write-CustomLog -Message "IP $IP is in whitelist - connection allowed" -LogFile $ActivityLog
                            }
                            
                            # Close the connection regardless
                            $client.Close()
                        }
                    } catch {
                        Write-Error "Error in connection handling: $_"
                    }
                    
                    # Small sleep to prevent high CPU usage
                    Start-Sleep -Milliseconds 100
                }
            } catch {
                Write-Error "Error in port $Port listener: $_"
            } finally {
                if ($listener) {
                    $listener.Stop()
                    Write-CustomLog -Message "Listener on port $Port has been stopped" -LogFile $ActivityLog
                }
            }
        }
        
        # Start the listener with the parameters
        Start-HoneyPortListener -Port $Port -WhiteList $WhiteList -ShouldBlock $Block -ActivityLog $ActivityLog -FirewallLog $FirewallLog
        
    } -ArgumentList $port, $WhiteList, $Block, $ActivityLogFile, $FirewallLogFile
    
    Write-CustomLog -Message "Job started for port $port" -LogFile $ActivityLogFile
}

# Create a simple test rule to verify firewall functionality
$testRuleName = "HoneyPort_TestRule"
Write-CustomLog -Message "Creating test firewall rule to verify functionality..." -LogFile $FirewallLogFile

try {
    # Remove test rule if it already exists
    Get-NetFirewallRule -DisplayName $testRuleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    
    # Create test rule
    $testRule = New-NetFirewallRule -DisplayName $testRuleName -Direction Inbound -Action Block -RemoteAddress "10.255.255.254" -Protocol TCP -Enabled True -Description "Test rule for HoneyPort script"
    
    if ($testRule) {
        Write-CustomLog -Message "Test rule created successfully. Firewall blocking functionality appears to be working." -LogFile $FirewallLogFile
        Write-Host "Firewall functionality verified successfully." -ForegroundColor Green
        
        # Clean up test rule
        $testRule | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    } else {
        Write-CustomLog -Message "Failed to create test rule. Firewall blocking functionality may not work." -LogFile $FirewallLogFile -Level "WARNING"
        Write-Host "WARNING: Failed to verify firewall functionality. IP blocking may not work." -ForegroundColor Yellow
    }
} catch {
    Write-CustomLog -Message "Error testing firewall functionality: $_" -LogFile $FirewallLogFile -Level "ERROR"
    Write-Host "ERROR: Firewall test failed. Please check the $FirewallLogFile for details." -ForegroundColor Red
}

Write-Host "HoneyPort script is now running. Monitoring ports: $($Ports -join ', ')" -ForegroundColor Cyan
Write-Host "Activity logs are being saved to $ActivityLogFile" -ForegroundColor White
Write-Host "Firewall logs are being saved to $FirewallLogFile" -ForegroundColor White
Write-Host "To test if blocking works, connect to one of the ports from a non-whitelisted IP, then check:"
Write-Host "  - Get-NetFirewallRule -DisplayName 'HoneyPort_Block_*'" -ForegroundColor Yellow
Write-Host "  - View the $FirewallLogFile file" -ForegroundColor Yellow
Write-Host "Use Get-Job to view job status. Use Stop-Job -Name 'HoneyPort_*' to stop monitoring."
