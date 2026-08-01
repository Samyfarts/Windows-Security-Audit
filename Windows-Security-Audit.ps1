$scriptFolder = if ($PSScriptRoot) {
    $PSScriptRoot
}
else {
    Get-Location
}

$report = Join-Path $scriptFolder "systemrapport.txt"
$htmlReport = Join-Path $scriptFolder "security-report.html"


# =========================================================
# TEXT REPORT
# =========================================================

"=== WINDOWS SECURITY AUDIT ===" |
    Out-File -FilePath $report -Encoding UTF8

"Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" |
    Out-File -FilePath $report -Append -Encoding UTF8


"`n=== OPERATIVSYSTEM ===" |
    Out-File -FilePath $report -Append -Encoding UTF8

Get-CimInstance Win32_OperatingSystem |
    Select-Object Caption, Version, BuildNumber, OSArchitecture |
    Format-List |
    Out-File -FilePath $report -Append -Encoding UTF8


"`n=== NETTVERK ===" |
    Out-File -FilePath $report -Append -Encoding UTF8

Get-NetIPConfiguration |
    Format-List |
    Out-File -FilePath $report -Append -Encoding UTF8


"`n=== NETTVERKSPROFIL ===" |
    Out-File -FilePath $report -Append -Encoding UTF8

Get-NetConnectionProfile |
    Select-Object Name, InterfaceAlias, NetworkCategory |
    Format-Table -AutoSize |
    Out-File -FilePath $report -Append -Encoding UTF8


"`n=== BRANNMUR ===" |
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


"`n=== LOKALE BRUKERE ===" |
    Out-File -FilePath $report -Append -Encoding UTF8

Get-LocalUser |
    Select-Object Name, Enabled, LastLogon, PasswordRequired |
    Format-Table -AutoSize |
    Out-File -FilePath $report -Append -Encoding UTF8


"`n=== LOKALE ADMINISTRATORER ===" |
    Out-File -FilePath $report -Append -Encoding UTF8

$adminGroup = Get-LocalGroup -SID "S-1-5-32-544"

Get-LocalGroupMember -Group $adminGroup |
    Select-Object Name, ObjectClass, PrincipalSource |
    Format-Table -AutoSize |
    Out-File -FilePath $report -Append -Encoding UTF8


"`n=== DISKPLASS ===" |
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


"`n=== AKTIVE TCP-FORBINDELSER ===" |
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

"`n=== AUTOMATISK SIKKERHETSVURDERING ===" |
    Out-File -FilePath $report -Append -Encoding UTF8

$firewallProfiles = Get-NetFirewallProfile
$defenderStatus = Get-MpComputerStatus
$networkProfiles = Get-NetConnectionProfile
$systemDrive = Get-Volume -DriveLetter C

$enabledAdmins = Get-LocalGroupMember -Group $adminGroup |
    Where-Object {
        $_.ObjectClass -eq "User" -and
        $_.PrincipalSource -eq "Local"
    } |
    ForEach-Object {
        $accountName = ($_.Name -split "\\")[-1]

        Get-LocalUser `
            -Name $accountName `
            -ErrorAction SilentlyContinue
    } |
    Where-Object {
        $_.Enabled -eq $true
    }


if ($firewallProfiles.Enabled -contains $false) {
    "[WARNING] En eller flere brannmurprofiler er deaktivert." |
        Out-File -FilePath $report -Append -Encoding UTF8
}
else {
    "[OK] Alle brannmurprofiler er aktivert." |
        Out-File -FilePath $report -Append -Encoding UTF8
}


if (-not $defenderStatus.RealTimeProtectionEnabled) {
    "[WARNING] Defender sanntidsbeskyttelse er deaktivert." |
        Out-File -FilePath $report -Append -Encoding UTF8
}
else {
    "[OK] Defender sanntidsbeskyttelse er aktivert." |
        Out-File -FilePath $report -Append -Encoding UTF8
}


if ($defenderStatus.AntivirusSignatureAge -gt 3) {
    "[WARNING] Defender-signaturene er eldre enn tre dager." |
        Out-File -FilePath $report -Append -Encoding UTF8
}
else {
    "[OK] Defender-signaturene er oppdaterte." |
        Out-File -FilePath $report -Append -Encoding UTF8
}


if ($networkProfiles.NetworkCategory -contains "Public") {
    "[REVIEW] Minst ett aktivt nettverk står som Public." |
        Out-File -FilePath $report -Append -Encoding UTF8
}
else {
    "[OK] Aktive nettverk bruker ikke Public-profil." |
        Out-File -FilePath $report -Append -Encoding UTF8
}


if (@($enabledAdmins).Count -gt 1) {
    "[REVIEW] Flere enn én aktiv lokal brukerkonto har administratorrettigheter." |
        Out-File -FilePath $report -Append -Encoding UTF8
}
else {
    "[OK] Antallet aktive lokale administratorbrukere er begrenset." |
        Out-File -FilePath $report -Append -Encoding UTF8
}


if ($systemDrive -and $systemDrive.Size -gt 0) {
    $freePercentage = (
        $systemDrive.SizeRemaining / $systemDrive.Size
    ) * 100

    if ($freePercentage -lt 15) {
        "[WARNING] Mindre enn 15 prosent ledig plass på C:-disken." |
            Out-File -FilePath $report -Append -Encoding UTF8
    }
    else {
        "[OK] C:-disken har tilstrekkelig ledig plass." |
            Out-File -FilePath $report -Append -Encoding UTF8
    }
}
else {
    "[REVIEW] Ledig plass på C:-disken kunne ikke vurderes." |
        Out-File -FilePath $report -Append -Encoding UTF8
}


if ($defenderStatus.FullScanAge -eq 4294967295) {
    "[REVIEW] Ingen fullstendig Defender-skanning er registrert." |
        Out-File -FilePath $report -Append -Encoding UTF8
}
elseif ($defenderStatus.FullScanAge -gt 30) {
    "[REVIEW] Fullstendig Defender-skanning er eldre enn 30 dager." |
        Out-File -FilePath $report -Append -Encoding UTF8
}
else {
    "[OK] Fullstendig Defender-skanning er nylig gjennomført." |
        Out-File -FilePath $report -Append -Encoding UTF8
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

<h1>Windows Security Audit</h1>

<p>
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
Generated by Windows Security Audit PowerShell Tool
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
Write-Host "Assessment results: $okCount OK, $reviewCount REVIEW, $warningCount WARNING"
Write-Host "Text report saved to: $report"
Write-Host "HTML report saved to: $htmlReport"