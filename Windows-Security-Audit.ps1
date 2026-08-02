[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputFolder,

    [Parameter()]
    [switch]$OpenReport
)

$toolName = "Windows Security Audit"
$toolVersion = "1.0.0"

function Add-AssessmentResult {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("OK", "REVIEW", "WARNING")]
        [string]$Status,

        [Parameter(Mandatory)]
        [string]$Message
    )

    "[$Status] $Message" |
        Out-File -FilePath $report -Append -Encoding UTF8
}

$scriptFolder = if ($PSScriptRoot) {
    $PSScriptRoot
}
else {
    Get-Location
}

if ([string]::IsNullOrWhiteSpace($OutputFolder)) {
    $OutputFolder = $scriptFolder
}

if (-not (Test-Path -Path $OutputFolder)) {
    New-Item `
        -Path $OutputFolder `
        -ItemType Directory `
        -Force |
        Out-Null
}

$OutputFolder = (Resolve-Path -Path $OutputFolder).Path

$report = Join-Path $OutputFolder "system-report.txt"
$htmlReport = Join-Path $OutputFolder "security-report.html"
$jsonReport = Join-Path $OutputFolder "security-report.json"

# =========================================================
# TEXT REPORT
# =========================================================

"=== WINDOWS SECURITY AUDIT ===" |
    Out-File -FilePath $report -Encoding UTF8

"Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" |
    Out-File -FilePath $report -Append -Encoding UTF8


"`n=== OPERATING SYSTEM ===" |
    Out-File -FilePath $report -Append -Encoding UTF8

Get-CimInstance Win32_OperatingSystem |
    Select-Object Caption, Version, BuildNumber, OSArchitecture |
    Format-List |
    Out-File -FilePath $report -Append -Encoding UTF8


"`n=== NETWORK ===" |
    Out-File -FilePath $report -Append -Encoding UTF8

Get-NetIPConfiguration |
    Format-List |
    Out-File -FilePath $report -Append -Encoding UTF8


"`n=== NETWORK PROFILE ===" |
    Out-File -FilePath $report -Append -Encoding UTF8

Get-NetConnectionProfile |
    Select-Object Name, InterfaceAlias, NetworkCategory |
    Format-Table -AutoSize |
    Out-File -FilePath $report -Append -Encoding UTF8


"`n=== FIREWALL ===" |
    Out-File -FilePath $report -Append -Encoding UTF8

Get-NetFirewallProfile |
    Select-Object Name, Enabled |
    Format-Table -AutoSize |
    Out-File -FilePath $report -Append -Encoding UTF8


"`n=== WINDOWS DEFENDER ===" |
    Out-File -FilePath $report -Append -Encoding UTF8

Get-MpComputerStatus |
    Select-Object AntivirusEnabled,
                  AMServiceEnabled,
                  AntispywareEnabled,
                  RealTimeProtectionEnabled,
                  BehaviorMonitorEnabled,
                  IoavProtectionEnabled,
                  NISEnabled,
                  AntivirusSignatureLastUpdated,
                  AntivirusSignatureAge,
                  QuickScanAge,
                  FullScanAge |
    Format-List |
    Out-File -FilePath $report -Append -Encoding UTF8


"`n=== LOCAL USERS ===" |
    Out-File -FilePath $report -Append -Encoding UTF8

Get-LocalUser |
    Select-Object Name, Enabled, LastLogon, PasswordRequired |
    Format-Table -AutoSize |
    Out-File -FilePath $report -Append -Encoding UTF8


"`n=== LOCAL ADMINISTRATORS ===" |
    Out-File -FilePath $report -Append -Encoding UTF8

$adminGroup = Get-LocalGroup -SID "S-1-5-32-544"

Get-LocalGroupMember -Group $adminGroup |
    Select-Object Name, ObjectClass, PrincipalSource |
    Format-Table -AutoSize |
    Out-File -FilePath $report -Append -Encoding UTF8


"`n=== DISK SPACE ===" |
    Out-File -FilePath $report -Append -Encoding UTF8

Get-Volume |
    Where-Object DriveLetter |
    Select-Object DriveLetter,
                  FileSystemLabel,
                  @{
                      Name = "FreeGB"
                      Expression = {
                          [math]::Round($_.SizeRemaining / 1GB, 2)
                      }
                  },
                  @{
                      Name = "SizeGB"
                      Expression = {
                          [math]::Round($_.Size / 1GB, 2)
                      }
                  } |
    Format-Table -AutoSize |
    Out-File -FilePath $report -Append -Encoding UTF8


"`n=== ACTIVE TCP CONNECTIONS ===" |
    Out-File -FilePath $report -Append -Encoding UTF8

Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
    ForEach-Object {
        $process = Get-Process `
            -Id $_.OwningProcess `
            -ErrorAction SilentlyContinue

        [PSCustomObject]@{
            LocalAddress  = $_.LocalAddress
            LocalPort     = $_.LocalPort
            RemoteAddress = $_.RemoteAddress
            RemotePort    = $_.RemotePort
            PID           = $_.OwningProcess
            ProcessName   = $process.ProcessName
        }
    } |
    Sort-Object ProcessName, RemoteAddress |
    Format-Table -AutoSize |
    Out-File -FilePath $report -Append -Encoding UTF8


# =========================================================
# SECURITY ASSESSMENT
# =========================================================

"`n=== AUTOMATIC SECURITY ASSESSMENT ===" |
    Out-File -FilePath $report -Append -Encoding UTF8


# =========================================================
# COLLECT SECURITY STATUS
# =========================================================

try {
    $firewallProfiles = Get-NetFirewallProfile -ErrorAction Stop
}
catch {
    $firewallProfiles = $null
}

try {
    $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
}
catch {
    $defenderStatus = $null
}

try {
    $networkProfiles = Get-NetConnectionProfile -ErrorAction Stop
}
catch {
    $networkProfiles = $null
}

try {
    $systemDrive = Get-Volume `
        -DriveLetter C `
        -ErrorAction Stop
}
catch {
    $systemDrive = $null
}

try {
    $enabledAdmins = Get-LocalGroupMember `
        -Group $adminGroup `
        -ErrorAction Stop |
        Where-Object {
            $_.ObjectClass -eq "User"
        } |
        ForEach-Object {
            $accountName = ($_.Name -split "\\")[-1]

            Get-LocalUser `
                -Name $accountName `
                -ErrorAction SilentlyContinue
        } |
        Where-Object {
            $_ -and $_.Enabled -eq $true
        }
}
catch {
    $enabledAdmins = $null
}


# =========================================================
# FIREWALL ASSESSMENT
# =========================================================

if (-not $firewallProfiles) {
    Add-AssessmentResult `
        -Status "REVIEW" `
        -Message "Windows Firewall status could not be retrieved."
}
elseif ($firewallProfiles.Enabled -contains $false) {
    Add-AssessmentResult `
        -Status "WARNING" `
        -Message "One or more firewall profiles are disabled."
}
else {
    Add-AssessmentResult `
        -Status "OK" `
        -Message "All firewall profiles are enabled."
}


# =========================================================
# DEFENDER REAL-TIME PROTECTION ASSESSMENT
# =========================================================

if (-not $defenderStatus) {
    Add-AssessmentResult `
        -Status "REVIEW" `
        -Message "Microsoft Defender status could not be retrieved."
}
elseif (-not $defenderStatus.RealTimeProtectionEnabled) {
    Add-AssessmentResult `
        -Status "WARNING" `
        -Message "Defender real-time protection is disabled."
}
else {
    Add-AssessmentResult `
        -Status "OK" `
        -Message "Defender real-time protection is enabled."
}


# =========================================================
# DEFENDER SIGNATURE ASSESSMENT
# =========================================================

if (-not $defenderStatus) {
    Add-AssessmentResult `
        -Status "REVIEW" `
        -Message "Defender signature status could not be evaluated."
}
elseif ($defenderStatus.AntivirusSignatureAge -gt 3) {
    Add-AssessmentResult `
        -Status "WARNING" `
        -Message "Defender signatures are older than three days."
}
else {
    Add-AssessmentResult `
        -Status "OK" `
        -Message "Defender signatures are up to date."
}


# =========================================================
# NETWORK PROFILE ASSESSMENT
# =========================================================

if (-not $networkProfiles) {
    Add-AssessmentResult `
        -Status "REVIEW" `
        -Message "The active network profile could not be retrieved."
}
elseif ($networkProfiles.NetworkCategory -contains "Public") {
    Add-AssessmentResult `
        -Status "REVIEW" `
        -Message "At least one active network is set to Public."
}
else {
    Add-AssessmentResult `
        -Status "OK" `
        -Message "Active networks are not using the Public profile."
}


# =========================================================
# LOCAL ADMINISTRATOR ASSESSMENT
# =========================================================

if ($null -eq $enabledAdmins) {
    Add-AssessmentResult `
        -Status "REVIEW" `
        -Message "Enabled local administrator accounts could not be evaluated."
}
elseif (@($enabledAdmins).Count -gt 1) {
    Add-AssessmentResult `
        -Status "REVIEW" `
        -Message "More than one active local user account has administrator privileges."
}
else {
    Add-AssessmentResult `
        -Status "OK" `
        -Message "The number of active local administrator users is limited."
}


# =========================================================
# DISK SPACE ASSESSMENT
# =========================================================

if ($systemDrive -and $systemDrive.Size -gt 0) {
    $freePercentage = (
        $systemDrive.SizeRemaining / $systemDrive.Size
    ) * 100

    if ($freePercentage -lt 15) {
        Add-AssessmentResult `
            -Status "WARNING" `
            -Message "Less than 15 percent free space remains on the system drive."
    }
    else {
        Add-AssessmentResult `
            -Status "OK" `
            -Message "The system drive has sufficient free space."
    }
}
else {
    Add-AssessmentResult `
        -Status "REVIEW" `
        -Message "Free space on the system drive could not be evaluated."
}


# =========================================================
# DEFENDER FULL SCAN ASSESSMENT
# =========================================================

if (-not $defenderStatus) {
    Add-AssessmentResult `
        -Status "REVIEW" `
        -Message "Defender full scan status could not be evaluated."
}
elseif ($defenderStatus.FullScanAge -eq 4294967295) {
    Add-AssessmentResult `
        -Status "REVIEW" `
        -Message "No complete Defender scan has been recorded."
}
elseif ($defenderStatus.FullScanAge -gt 30) {
    Add-AssessmentResult `
        -Status "REVIEW" `
        -Message "The latest complete Defender scan is older than 30 days."
}
else {
    Add-AssessmentResult `
        -Status "OK" `
        -Message "A complete Defender scan was performed recently."
}


# =========================================================
# WINDOWS UPDATE ASSESSMENT
# =========================================================

"`n=== WINDOWS UPDATE ===" |
    Out-File -FilePath $report -Append -Encoding UTF8

try {
    $latestUpdate = Get-HotFix -ErrorAction Stop |
        Where-Object {
            $_.InstalledOn
        } |
        Sort-Object InstalledOn -Descending |
        Select-Object -First 1

    if (-not $latestUpdate) {
        Add-AssessmentResult `
            -Status "REVIEW" `
            -Message "No installed Windows updates were found."
    }
    else {
        $updateAge = (
            New-TimeSpan `
                -Start $latestUpdate.InstalledOn `
                -End (Get-Date)
        ).Days

        "Latest update: $($latestUpdate.HotFixID)" |
            Out-File -FilePath $report -Append -Encoding UTF8

        "Installed: $($latestUpdate.InstalledOn)" |
            Out-File -FilePath $report -Append -Encoding UTF8

        "Age in days: $updateAge" |
            Out-File -FilePath $report -Append -Encoding UTF8

        if ($updateAge -gt 45) {
            Add-AssessmentResult `
                -Status "REVIEW" `
                -Message "The latest installed Windows update is older than 45 days."
        }
        else {
            Add-AssessmentResult `
                -Status "OK" `
                -Message "A Windows update was installed within the last 45 days."
        }
    }
}
catch {
    Add-AssessmentResult `
        -Status "REVIEW" `
        -Message "Windows Update information could not be retrieved."
}


# =========================================================
# BITLOCKER ASSESSMENT
# =========================================================

"`n=== BITLOCKER ===" |
    Out-File -FilePath $report -Append -Encoding UTF8

try {
    $bitLockerVolume = Get-BitLockerVolume `
        -MountPoint "C:" `
        -ErrorAction Stop

    "Volume status: $($bitLockerVolume.VolumeStatus)" |
        Out-File -FilePath $report -Append -Encoding UTF8

    "Protection status: $($bitLockerVolume.ProtectionStatus)" |
        Out-File -FilePath $report -Append -Encoding UTF8

    "Encryption percentage: $($bitLockerVolume.EncryptionPercentage)" |
        Out-File -FilePath $report -Append -Encoding UTF8

    if ($bitLockerVolume.ProtectionStatus -eq "On") {
        Add-AssessmentResult `
            -Status "OK" `
            -Message "BitLocker protection is enabled on the system drive."
    }
    elseif ($bitLockerVolume.VolumeStatus -eq "FullyDecrypted") {
        Add-AssessmentResult `
            -Status "WARNING" `
            -Message "BitLocker encryption is not enabled on the system drive."
    }
    else {
        Add-AssessmentResult `
            -Status "REVIEW" `
            -Message "BitLocker protection is not currently active on the system drive."
    }
}
catch {
    Add-AssessmentResult `
        -Status "REVIEW" `
        -Message "BitLocker status could not be retrieved."
}

# =========================================================
# BUILD HTML REPORT
# =========================================================

$assessmentLines = @(
    Get-Content -Path $report |
        Where-Object {
            $_ -match "^\[(OK|REVIEW|WARNING)\]"
        }
)

$okCount = @(
    $assessmentLines |
        Where-Object {
            $_ -match "^\[OK\]"
        }
).Count

$reviewCount = @(
    $assessmentLines |
        Where-Object {
            $_ -match "^\[REVIEW\]"
        }
).Count

$warningCount = @(
    $assessmentLines |
        Where-Object {
            $_ -match "^\[WARNING\]"
        }
).Count


$assessmentRows = foreach ($line in $assessmentLines) {
    if ($line -match "^\[(OK|REVIEW|WARNING)\]\s*(.*)$") {
        [PSCustomObject]@{
            Status  = $matches[1]
            Finding = $matches[2]
        }
    }
}

# =========================================================
# BUILD JSON REPORT
# =========================================================

$jsonContent = [PSCustomObject]@{
    Tool = [PSCustomObject]@{
        Name    = $toolName
        Version = $toolVersion
    }

    Computer = [PSCustomObject]@{
        Name = $env:COMPUTERNAME
    }

    Generated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    Summary = [PSCustomObject]@{
        OK      = $okCount
        Review  = $reviewCount
        Warning = $warningCount
        Total   = $assessmentRows.Count
    }

    Findings = @(
        $assessmentRows | ForEach-Object {
            [PSCustomObject]@{
                Status  = $_.Status
                Finding = $_.Finding
            }
        }
    )
}

$jsonContent |
    ConvertTo-Json -Depth 5 |
    Set-Content -Path $jsonReport -Encoding UTF8


$assessmentHtml = foreach ($item in $assessmentRows) {
    $statusClass = $item.Status.ToLower()

@"
<tr>
    <td class="$statusClass">$($item.Status)</td>
    <td>$($item.Finding)</td>
</tr>
"@
}


$htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<title>Windows Security Audit</title>

<style>
body {
    font-family: Arial, sans-serif;
    background-color: #f4f6f8;
    margin: 0;
    padding: 30px;
    color: #222;
}

.container {
    max-width: 1000px;
    margin: auto;
    background-color: white;
    padding: 30px;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.08);
}

h1 {
    margin-top: 0;
}

.summary {
    display: flex;
    gap: 15px;
    margin: 25px 0;
}

.card {
    flex: 1;
    padding: 18px;
    border-radius: 6px;
    text-align: center;
    font-size: 18px;
    font-weight: bold;
}

.ok-card {
    background-color: #d9f2df;
}

.review-card {
    background-color: #fff3cd;
}

.warning-card {
    background-color: #f8d7da;
}

table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 20px;
}

th,
td {
    padding: 12px;
    border: 1px solid #ddd;
    text-align: left;
}

th {
    background-color: #e9ecef;
}

.ok {
    color: #146c2e;
    font-weight: bold;
}

.review {
    color: #8a6d00;
    font-weight: bold;
}

.warning {
    color: #a61b29;
    font-weight: bold;
}

.footer {
    margin-top: 30px;
    color: #666;
    font-size: 13px;
}

@media (max-width: 700px) {
    .summary {
        flex-direction: column;
    }

    body {
        padding: 10px;
    }

    .container {
        padding: 18px;
    }
}
</style>
</head>

<body>
<div class="container">

<h1>$toolName</h1>

<p>
<strong>Version:</strong> $toolVersion<br>
<strong>Computer:</strong> $env:COMPUTERNAME<br>
<strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
</p>

<div class="summary">
    <div class="card ok-card">
        OK<br>
        $okCount
    </div>

    <div class="card review-card">
        REVIEW<br>
        $reviewCount
    </div>

    <div class="card warning-card">
        WARNING<br>
        $warningCount
    </div>
</div>

<h2>Security assessment</h2>

<table>
<thead>
<tr>
    <th>Status</th>
    <th>Finding</th>
</tr>
</thead>

<tbody>
$($assessmentHtml -join "`n")
</tbody>
</table>

<div class="footer">
Generated by $toolName
</div>

</div>
</body>
</html>
"@


$htmlContent |
    Set-Content -Path $htmlReport -Encoding UTF8


# =========================================================
# COMPLETION
# =========================================================

Write-Host "Security audit completed."
Write-Host "Tool version: $toolVersion"
Write-Host "Assessment results: $okCount OK, $reviewCount REVIEW, $warningCount WARNING"
Write-Host "Text report saved to: $report"
Write-Host "HTML report saved to: $htmlReport"
Write-Host "JSON report saved to: $jsonReport"

if ($OpenReport) {
    Start-Process -FilePath $htmlReport
}