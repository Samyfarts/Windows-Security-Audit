$scriptFolder = if ($PSScriptRoot) {
    $PSScriptRoot
}
else {
    Get-Location
}

$report = Join-Path $scriptFolder "systemrapport.txt"

$htmlReport = Join-Path $scriptFolder "security-report.html"

"=== WINDOWS SECURITY AUDIT ===" | Out-File $report
"Generated: $(Get-Date)" | Out-File $report -Append


"`n=== OPERATIVSYSTEM ===" | Out-File $report -Append

Get-CimInstance Win32_OperatingSystem |
    Select-Object Caption, Version, BuildNumber, OSArchitecture |
    Format-List |
    Out-File $report -Append


"`n=== NETTVERK ===" | Out-File $report -Append

Get-NetIPConfiguration |
    Format-List |
    Out-File $report -Append


"`n=== NETTVERKSPROFIL ===" | Out-File $report -Append

Get-NetConnectionProfile |
    Select-Object Name, InterfaceAlias, NetworkCategory |
    Format-Table -AutoSize |
    Out-File $report -Append


"`n=== BRANNMUR ===" | Out-File $report -Append

Get-NetFirewallProfile |
    Select-Object Name, Enabled |
    Format-Table -AutoSize |
    Out-File $report -Append


"`n=== WINDOWS DEFENDER ===" | Out-File $report -Append

Get-MpComputerStatus |
    Select-Object AntivirusEnabled,
                  AMServiceEnabled,
                  AntispywareEnabled,
                  RealTimeProtectionEnabled,
                  BehaviorMonitorEnabled,
                  IoavProtectionEnabled,
                  NISEnabled,
                  AntivirusSignatureLastUpdated,
                  QuickScanAge,
                  FullScanAge |
    Format-List |
    Out-File $report -Append


"`n=== LOKALE BRUKERE ===" | Out-File $report -Append

Get-LocalUser |
    Select-Object Name, Enabled, LastLogon, PasswordRequired |
    Format-Table -AutoSize |
    Out-File $report -Append


"`n=== LOKALE ADMINISTRATORER ===" | Out-File $report -Append

$adminGroup = Get-LocalGroup -SID "S-1-5-32-544"

Get-LocalGroupMember -Group $adminGroup |
    Select-Object Name, ObjectClass, PrincipalSource |
    Format-Table -AutoSize |
    Out-File $report -Append


"`n=== DISKPLASS ===" | Out-File $report -Append

Get-Volume |
    Select-Object DriveLetter,
                  FileSystemLabel,
                  @{Name="FreeGB"; Expression={[math]::Round($_.SizeRemaining / 1GB, 2)}},
                  @{Name="SizeGB"; Expression={[math]::Round($_.Size / 1GB, 2)}} |
    Format-Table -AutoSize |
    Out-File $report -Append


"`n=== AKTIVE TCP-FORBINDELSER ===" | Out-File $report -Append

Get-NetTCPConnection -State Established |
    ForEach-Object {
        $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue

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
    Out-File $report -Append
"`n=== AUTOMATISK SIKKERHETSVURDERING ===" |
    Out-File $report -Append

$firewallProfiles = Get-NetFirewallProfile
$defenderStatus = Get-MpComputerStatus
$networkProfiles = Get-NetConnectionProfile
$systemDrive = Get-Volume -DriveLetter C

$adminGroup = Get-LocalGroup -SID "S-1-5-32-544"

$enabledAdmins = Get-LocalGroupMember -Group $adminGroup |
    Where-Object {
        $_.ObjectClass -eq "User" -and
        $_.PrincipalSource -eq "Local"
    } |
    ForEach-Object {
        $accountName = ($_.Name -split "\\")[-1]
        Get-LocalUser -Name $accountName -ErrorAction SilentlyContinue
    } |
    Where-Object {
        $_.Enabled -eq $true
    }

if ($firewallProfiles.Enabled -contains $false) {
    "[WARNING] En eller flere brannmurprofiler er deaktivert." |
        Out-File $report -Append
}
else {
    "[OK] Alle brannmurprofiler er aktivert." |
        Out-File $report -Append
}

if (-not $defenderStatus.RealTimeProtectionEnabled) {
    "[WARNING] Defender sanntidsbeskyttelse er deaktivert." |
        Out-File $report -Append
}
else {
    "[OK] Defender sanntidsbeskyttelse er aktivert." |
        Out-File $report -Append
}

if ($defenderStatus.AntivirusSignatureAge -gt 3) {
    "[WARNING] Defender-signaturene er eldre enn tre dager." |
        Out-File $report -Append
}
else {
    "[OK] Defender-signaturene er oppdaterte." |
        Out-File $report -Append
}

if ($networkProfiles.NetworkCategory -contains "Public") {
    "[REVIEW] Minst ett aktivt nettverk står som Public." |
        Out-File $report -Append
}
else {
    "[OK] Aktive nettverk bruker ikke Public-profil." |
        Out-File $report -Append
}

if (@($enabledAdmins).Count -gt 1) {
    "[REVIEW] Flere enn én aktiv brukerkonto har administratorrettigheter." |
        Out-File $report -Append
}
else {
    "[OK] Antallet aktive administratorbrukere er begrenset." |
        Out-File $report -Append
}

$freePercentage = (
    $systemDrive.SizeRemaining / $systemDrive.Size
) * 100

if ($freePercentage -lt 15) {
    "[WARNING] Mindre enn 15 prosent ledig plass på C:-disken." |
        Out-File $report -Append
}
else {
    "[OK] C:-disken har tilstrekkelig ledig plass." |
        Out-File $report -Append
}

if ($defenderStatus.FullScanAge -eq 4294967295) {
    "[REVIEW] Ingen fullstendig Defender-skanning er registrert." |
        Out-File $report -Append
}
elseif ($defenderStatus.FullScanAge -gt 30) {
    "[REVIEW] Fullstendig Defender-skanning er eldre enn 30 dager." |
        Out-File $report -Append
}
else {
    "[OK] Fullstendig Defender-skanning er nylig gjennomført." |
        Out-File $report -Append
}

$htmlContent |
    Set-Content -Path $htmlReport -Encoding UTF8

Write-Host "Security audit completed."
Write-Host "Text report saved to: $report"
Write-Host "HTML report saved to: $htmlReport"