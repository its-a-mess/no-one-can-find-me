# Vision API Client Class
class VisionClient {
    [string]$IP
    [string]$Username
    [string]$Password
    [string]$RootPassword
    [object]$Session
    
    VisionClient([string]$ip, [string]$username, [string]$password, [string]$rootPassword) {
        $this.IP = $ip
        $this.Username = $username
        $this.Password = $password
        $this.RootPassword = $rootPassword
        $this.Login()
    }

    [void]Login() {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        Add-Type @"
            using System.Net;
            using System.Security.Cryptography.X509Certificates;
            public class TrustAllCertsPolicy : ICertificatePolicy {
                public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) {
                    return true;
                }
            }
"@
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

        $loginUrl = "https://$($this.IP)/mgmt/system/user/login"
        $body = @{
            username = $this.Username
            password = $this.Password
        } | ConvertTo-Json

        try {
            $response = Invoke-RestMethod -Uri $loginUrl -Method Post -Body $body -ContentType "application/json"
            if ($response.status -eq "ok") {
                $this.Session = @{
                    Headers = @{
                        "Content-Type" = "application/json"
                        "JSESSIONID" = $response.jsessionid
                    }
                }
                Write-Host "Vision login successful"
            }
        }
        catch {
            throw "Login failed: $_"
        }
    }

    [object]GetAttackData([string]$deviceIP, [datetime]$startTime, [datetime]$endTime, [string[]]$policies) {
        $url = "https://$($this.IP)/mgmt/monitor/reporter/reports-ext/DP_ATTACK_REPORTS"
        
        # Create policy filters
        $policyFilters = $policies | ForEach-Object {
            @{
                type = "termFilter"
                field = "policyName"
                value = $_
            }
        }

        $body = @{
            criteria = @(
                @{
                    type = "timeFilter"
                    field = "endTime"
                    lower = [int][double]::Parse((Get-Date -Date $startTime -UFormat %s))
                    upper = [int][double]::Parse((Get-Date -Date $endTime -UFormat %s))
                },
                @{
                    type = "termFilter"
                    field = "deviceIp"
                    value = $deviceIP
                }
            ) + $policyFilters
            pagination = @{
                size = 1000
                page = 0
            }
        } | ConvertTo-Json -Depth 10

        $response = Invoke-RestMethod -Uri $url -Method Post -Body $body -Headers $this.Session.Headers -ContentType "application/json"
        return $response
    }

    [object]GetDeviceData([string]$deviceIP) {
        $url = "https://$($this.IP)/mgmt/device/byip/$deviceIP/config/deviceaccess"
        try {
            $response = Invoke-RestMethod -Uri $url -Method Get -Headers $this.Session.Headers -ContentType "application/json"
            return $response
        }
        catch {
            throw "Failed to get device data: $_"
        }
    }
}

# PSCP File Transfer Class
class PSCPClient {
    [string]$DeviceIP
    [string]$Username
    [string]$Password
    [int]$Port
    [string]$RemotePath = '/disk/var/attacklog/bdos'
    [string]$TempFolder = "./Temp/"
    [string]$PSCPPath = "C:\Program Files\PuTTY\pscp.exe"

    PSCPClient([string]$deviceIP, [string]$username, [string]$password, [int]$port) {
        $this.DeviceIP = $deviceIP
        $this.Username = $username
        $this.Password = $password
        $this.Port = $port

        if (-not (Test-Path $this.PSCPPath)) {
            throw "PSCP not found at $($this.PSCPPath). Please ensure PuTTY is installed."
        }
        if (-not (Test-Path $this.TempFolder)) {
            New-Item -ItemType Directory -Path $this.TempFolder | Out-Null
        }
    }

    [array]GetAttackLogs([int]$startYear, [int]$fromMonth, [int]$toMonth = 0) {
        $foundFiles = @()
        
        try {
            # Create pattern for file matching
            $pattern = if ($toMonth -gt 0) {
                "BDOS$startYear[$fromMonth-$toMonth]"
            } else {
                "BDOS$startYear$fromMonth"
            }

            # List remote directory using plink
            $plinkPath = "C:\Program Files\PuTTY\plink.exe"
            $remoteCmd = "ls -1 $($this.RemotePath)/BDOS$startYear*"
            
            $files = & $plinkPath -ssh -P $this.Port -l $this.Username -pw $this.Password -batch -no-antispoof $this.DeviceIP $remoteCmd 2>$null

            foreach ($file in $files) {
                $fileName = Split-Path $file.Trim() -Leaf
                if ($fileName -match $pattern) {
                    $this.RemotePath = "$($this.RemotePath)/$fileName"
                    $localPath = Join-Path $this.TempFolder $fileName

                    Write-Host "Downloading $fileName..."
                    
                    & $this.PSCPPath -P $this.Port -pw $this.Password -batch -no-antispoof `
                        "$($this.Username)@$($this.DeviceIP):$this.RemotePath" `
                        $localPath 2>$null

                    if ($LASTEXITCODE -eq 0) {
                        $foundFiles += $fileName
                        Write-Host "Downloaded $fileName successfully"
                    }
                }
            }
        }
        catch {
            Write-Host "Error during file transfer: $_" -ForegroundColor Red
        }

        return $foundFiles
    }
}

# HTML Report Generation Function
function New-HTMLReport {
    param(
        [object]$AttackData,
        [array]$LogFiles,
        [string]$OutputPath
    )
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Attack Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .chart { width: 100%; height: 400px; margin-bottom: 20px; }
        .section { margin-bottom: 30px; }
    </style>
</head>
<body>
    <h1>Attack Analysis Report</h1>
"@

    # Add attack log files section
    $html += "<div class='section'>"
    $html += "<h2>Attack Log Files</h2>"
    $html += "<table><tr><th>File Name</th><th>Download Time</th></tr>"
    foreach ($file in $LogFiles) {
        $fileInfo = Get-Item (Join-Path "./Temp" $file)
        $html += "<tr><td>$($fileInfo.Name)</td><td>$($fileInfo.CreationTime)</td></tr>"
    }
    $html += "</table></div>"

    # Add attack summary
    $html += "<div class='section'>"
    $html += "<h2>Attack Summary</h2>"
    $html += "<table>"
    if ($AttackData.data) {
        $html += "<tr><th>Total Attacks</th><td>$($AttackData.data.Count)</td></tr>"
    }
    $html += "</table></div>"

    # Add attack details
    if ($AttackData.data) {
        $html += "<div class='section'>"
        $html += "<h2>Attack Details</h2>"
        $html += "<table><tr><th>Time</th><th>Type</th><th>Source</th><th>Destination</th><th>Action</th></tr>"
        foreach ($attack in $AttackData.data) {
            $html += "<tr>"
            $html += "<td>$($attack.startTime)</td>"
            $html += "<td>$($attack.attackType)</td>"
            $html += "<td>$($attack.sourceIP)</td>"
            $html += "<td>$($attack.destIP)</td>"
            $html += "<td>$($attack.action)</td>"
            $html += "</tr>"
        }
        $html += "</table></div>"
    }

    # Add BDOS log analysis section
    $html += "<div class='section'>"
    $html += "<h2>BDOS Log Analysis</h2>"
    $html += "<table><tr><th>Time</th><th>Attack Type</th><th>Source IP</th><th>Destination IP</th><th>Action</th><th>Packets</th></tr>"
    
    foreach ($file in $LogFiles) {
        $content = Get-Content (Join-Path "./Temp" $file)
        foreach ($line in $content) {
            if ($line -match '\[(.*?)\].*?attack_type=(.*?),.*?src_ip=(.*?),.*?dst_ip=(.*?),.*?action=(.*?),.*?packets=(\d+)') {
                $html += "<tr>"
                $html += "<td>$($matches[1])</td>"
                $html += "<td>$($matches[2])</td>"
                $html += "<td>$($matches[3])</td>"
                $html += "<td>$($matches[4])</td>"
                $html += "<td>$($matches[5])</td>"
                $html += "<td>$($matches[6])</td>"
                $html += "</tr>"
            }
        }
    }
    $html += "</table></div>"

    $html += "</body></html>"

    # Create Reports directory if it doesn't exist
    $reportDir = Split-Path $OutputPath -Parent
    if (-not (Test-Path $reportDir)) {
        New-Item -ItemType Directory -Path $reportDir | Out-Null
    }

    $html | Out-File -FilePath $OutputPath -Encoding UTF8
}

# User Input Functions
function Get-UserTimeRange {
    Write-Host "`nSelect time range type:"
    Write-Host "1. Last X hours"
    Write-Host "2. Date range"
    Write-Host "3. Epoch range"
    
    $choice = Read-Host "Enter your choice (1-3)"
    
    switch ($choice) {
        "1" {
            $hours = Read-Host "Enter number of hours"
            $endTime = Get-Date
            $startTime = $endTime.AddHours(-[int]$hours)
            return @($startTime, $endTime)
        }
        "2" {
            $startTime = Read-Host "Enter start time (format: dd-MM-yyyy HH:mm:ss)"
            $endTime = Read-Host "Enter end time (format: dd-MM-yyyy HH:mm:ss)"
            return @([datetime]::ParseExact($startTime, "dd-MM-yyyy HH:mm:ss", $null), 
                    [datetime]::ParseExact($endTime, "dd-MM-yyyy HH:mm:ss", $null))
        }
        "3" {
            $startEpoch = Read-Host "Enter start epoch time"
            $endEpoch = Read-Host "Enter end epoch time"
            return @([datetime]::UnixEpoch.AddSeconds($startEpoch), 
                    [datetime]::UnixEpoch.AddSeconds($endEpoch))
        }
        default {
            throw "Invalid choice"
        }
    }
}

function Get-DefenseProDevices {
    $devices = @{}
    do {
        $deviceIP = Read-Host "`nEnter DefensePro IP (or press Enter to finish)"
        if ($deviceIP) {
            $policies = Read-Host "Enter policies for this device (comma-separated)"
            $devices[$deviceIP] = $policies.Split(',').Trim()
        }
    } while ($deviceIP)
    
    return $devices
}

# Main Script Execution
$ErrorActionPreference = "Stop"

try {
    # Get Vision credentials
    Write-Host "`nEnter Vision credentials:"
    $visionIP = Read-Host "Vision IP"
    $visionUsername = Read-Host "Username"
    $visionPassword = Read-Host "Password" -AsSecureString
    $visionRootPassword = Read-Host "Root Password" -AsSecureString

    # Convert SecureString to plain text for API usage
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($visionPassword)
    $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($visionRootPassword)
    $plainRootPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

    # Initialize Vision client
    $vision = [VisionClient]::new($visionIP, $visionUsername, $plainPassword, $plainRootPassword)

    # Get time range from user
    $timeRange = Get-UserTimeRange
    $startTime = $timeRange[0]
    $endTime = $timeRange[1]

    # Get DefensePro devices and policies
    $devices = Get-DefenseProDevices

    # Process each DefensePro device
    foreach ($device in $devices.GetEnumerator()) {
        Write-Host "`nProcessing device: $($device.Key)"
        
        try {
            # Get device credentials and download log files
            $dpData = $vision.GetDeviceData($device.Key)
            
            if ($null -eq $dpData -or $null -eq $dpData.deviceSetup) {
                Write-Host "Warning: Could not get device data for $($device.Key), skipping..." -ForegroundColor Yellow
                continue
            }

            $pscpClient = [PSCPClient]::new(
                $device.Key,
                $dpData.deviceSetup.deviceAccess.httpsUsername,
                $dpData.deviceSetup.deviceAccess.httpsPassword,
                [int]$dpData.deviceSetup.deviceAccess.cliPort
            )

            # Get attack logs
            $startYear = $startTime.Year
            $fromMonth = $startTime.Month
            $toMonth = if ($endTime.Year -eq $startYear) { $endTime.Month } else { 0 }
            
            $logFiles = $pscpClient.GetAttackLogs($startYear, $fromMonth, $toMonth)
            Write-Host "Retrieved log files: $($logFiles -join ', ')"

            # Get attack data from Vision with policies
            $attackData = $vision.GetAttackData($device.Key, $startTime, $endTime, $device.Value)

            # Generate comprehensive report
            $reportPath = "Reports\Attack_Report_$($device.Key)_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
            New-HTMLReport -AttackData $attackData -LogFiles $logFiles -OutputPath $reportPath
            Write-Host "Report generated: $reportPath"
        }
        catch {
            Write-Host "Error processing device $($device.Key): $_" -ForegroundColor Red
        }
    }

    Write-Host "`nAll devices processed successfully."
}
catch {
    Write-Host "Error: $_" -ForegroundColor Red
    exit 1
}
