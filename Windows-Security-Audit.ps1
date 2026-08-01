$report = "$HOME\Documents\systemrapport.txt"

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


Write-Host "Security audit completed."
Write-Host "Report saved to: $report"