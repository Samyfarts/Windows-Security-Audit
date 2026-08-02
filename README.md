# Windows Security Audit

A PowerShell-based Windows security auditing tool that collects system information, evaluates key security settings, and generates structured reports.

The project was created as a practical exercise in PowerShell scripting, Windows administration, networking, automation, and cybersecurity.

> Current development version: `1.0.0-dev`

## Overview

Windows Security Audit examines a local Windows computer and performs nine automatic security checks.

The results are classified as:

- `OK` – the setting meets the current audit criteria
- `REVIEW` – the setting should be reviewed or could not be evaluated
- `WARNING` – a potentially important security issue was detected

The tool generates reports in three formats:

- plain text
- HTML
- JSON

## Features

- Collects Windows system and network information
- Performs nine automatic security assessments
- Generates TXT, HTML, and JSON reports
- Presents findings in a visual HTML dashboard
- Supports a custom report output folder
- Can automatically open the HTML report
- Uses structured `OK`, `REVIEW`, and `WARNING` results
- Handles unavailable commands without stopping the complete audit
- Records the tool version and report generation time

## Information Collected

The script collects information about:

- Windows edition, version, and build number
- Computer name
- Active network adapters
- IPv4 and IPv6 addresses
- Default gateway
- DNS servers
- Active network profile
- Windows Firewall profiles
- Microsoft Defender status
- Local user accounts
- Members of the local Administrators group
- Available disk space
- Active TCP connections
- Processes associated with active connections
- Latest installed Windows update
- BitLocker status for the system drive

## Security Checks

The automatic assessment currently includes nine checks:

1. Windows Firewall profiles
2. Microsoft Defender real-time protection
3. Microsoft Defender signature age
4. Active network profile
5. Enabled local administrator accounts
6. Available space on the system drive
7. Microsoft Defender full scan age
8. Latest installed Windows update age
9. BitLocker protection status

## Assessment Criteria

### Windows Firewall

- `OK` when all firewall profiles are enabled
- `WARNING` when one or more firewall profiles are disabled
- `REVIEW` when the firewall status cannot be retrieved

### Defender real-time protection

- `OK` when real-time protection is enabled
- `WARNING` when real-time protection is disabled
- `REVIEW` when Defender status cannot be retrieved

### Defender signatures

- `OK` when antivirus signatures are no more than three days old
- `WARNING` when antivirus signatures are older than three days
- `REVIEW` when the signature status cannot be evaluated

### Network profile

- `OK` when active connections are not using the Public profile
- `REVIEW` when an active connection uses the Public profile
- `REVIEW` when the network profile cannot be retrieved

A Public profile is not automatically insecure, but it may require review depending on the network and intended configuration.

### Local administrators

- `OK` when no more than one enabled local user has administrator privileges
- `REVIEW` when more than one enabled local user has administrator privileges
- `REVIEW` when administrator accounts cannot be evaluated

### Disk space

- `OK` when at least 15 percent of the system drive is free
- `WARNING` when less than 15 percent is free
- `REVIEW` when disk space cannot be evaluated

### Defender full scan

- `OK` when a complete Defender scan was performed within the last 30 days
- `REVIEW` when the scan is older than 30 days
- `REVIEW` when no complete scan has been recorded
- `REVIEW` when the scan status cannot be evaluated

### Windows Update

- `OK` when a Windows update was installed within the last 45 days
- `REVIEW` when the latest detected update is older than 45 days
- `REVIEW` when update information cannot be retrieved

### BitLocker

- `OK` when BitLocker protection is enabled on the system drive
- `WARNING` when the system drive is fully decrypted
- `REVIEW` when encryption exists but protection is not active
- `REVIEW` when BitLocker status cannot be retrieved

## Requirements

- Windows 10 or Windows 11
- Windows PowerShell 5.1 or PowerShell 7
- Permission to run local PowerShell scripts
- Administrator privileges recommended

The tool uses Windows-specific PowerShell commands and is not intended for Linux or macOS.

## Administrator Privileges

Run PowerShell or Visual Studio Code as Administrator for the most complete results.

Some checks may return `REVIEW` without elevated privileges, particularly:

- BitLocker status
- Local administrator account evaluation
- Some Defender information
- Some network and system configuration data

## Usage

Clone the repository:

```powershell
git clone https://github.com/Samyfarts/Windows-Security-Audit.git
```

Open the project folder:

```powershell
Set-Location "$HOME\Documents\Windows-Security-Audit"
```

Run the audit:

```powershell
.\Windows-Security-Audit.ps1
```

### Open the HTML report automatically

```powershell
.\Windows-Security-Audit.ps1 -OpenReport
```

### Save reports to a custom folder

```powershell
.\Windows-Security-Audit.ps1 `
    -OutputFolder ".\reports"
```

### Save reports to a custom folder and open the HTML report

```powershell
.\Windows-Security-Audit.ps1 `
    -OutputFolder ".\reports" `
    -OpenReport
```

## Parameters

| Parameter | Type | Description |
|---|---|---|
| `-OutputFolder` | String | Selects the directory where reports are saved |
| `-OpenReport` | Switch | Opens the generated HTML report after the audit completes |

When `-OutputFolder` is not provided, reports are saved in the script directory.

## Output Files

The script generates the following files:

| File | Description |
|---|---|
| `systemrapport.txt` | Detailed text-based system and security report |
| `security-report.html` | Visual HTML summary of the security assessment |
| `security-report.json` | Structured report for automation and further processing |

Generated report files are intended to remain local and are excluded from version control.

## HTML Report

The HTML report contains:

- tool version
- computer name
- report generation time
- total number of `OK` results
- total number of `REVIEW` results
- total number of `WARNING` results
- a table containing all assessment findings

## Report Preview

![Windows Security Audit HTML report](docs/security-report-preview.jpeg)

## JSON Structure

The JSON report contains:

- tool name
- tool version
- computer name
- report generation time
- assessment totals
- individual findings and status values

Example:

```json
{
  "Tool": {
    "Name": "Windows Security Audit",
    "Version": "1.0.0"
  },
  "Computer": {
    "Name": "COMPUTER-NAME"
  },
  "Generated": "2026-08-02 10:35:24",
  "Summary": {
    "OK": 9,
    "Review": 0,
    "Warning": 0,
    "Total": 9
  },
  "Findings": [
    {
      "Status": "OK",
      "Finding": "All firewall profiles are enabled."
    }
  ]
}
```

## Project Structure

```text
Windows-Security-Audit/
├── Windows-Security-Audit.ps1
├── README.md
├── .gitignore
└── docs/
    └── security-report-preview.jpeg
```

Generated locally:

```text
reports/
├── systemrapport.txt
├── security-report.html
└── security-report.json
```

## Error Handling

Security information is collected using separate error-handling blocks.

When a command fails or a Windows feature is unavailable, the script records a `REVIEW` result instead of terminating the complete audit.

This allows the remaining security checks and reports to be completed.

## Limitations

- The tool audits only the local computer
- The assessment criteria are general baseline checks, not a complete security standard
- A result marked `OK` does not guarantee that the computer is fully secure
- Windows configurations differ between editions and environments
- Some commands require administrator privileges
- BitLocker may not be available on every Windows edition
- `Get-HotFix` does not represent every possible Windows update mechanism
- Third-party antivirus products may affect Microsoft Defender results

## Future Development

Possible future features include:

- remote computer auditing
- comparison against a saved security baseline
- configurable assessment thresholds
- CSV report export
- command-line summary options
- logging
- additional Windows security checks
- support for auditing multiple computers

## Security Notice

The reports may contain sensitive system information, including:

- computer name
- IP addresses
- local user accounts
- administrator group membership
- network configuration
- active connections
- running process information

Review reports before sharing them publicly.

## Educational Purpose

This project is primarily intended for learning and portfolio demonstration.

It demonstrates practical experience with:

- PowerShell
- Windows administration
- system information collection
- security assessment logic
- structured error handling
- HTML report generation
- JSON serialization
- Git and GitHub
- technical documentation

## Version 1.0

Version 1.0 includes:

- nine automatic security checks
- TXT, HTML, and JSON reports
- configurable output folder
- automatic HTML report opening
- structured error handling
- report metadata and version information

## Author

Developed by André Rutledal as part of continued studies in network administration, IT security, and cybersecurity.