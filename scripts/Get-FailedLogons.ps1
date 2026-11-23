<#
.SYNOPSIS
    Reports failed logons and account lockouts from a domain controller.
.DESCRIPTION
    Reads Security events 4625, 4771, 4776, and 4740 and prints the time,
    event ID, user, source IP, workstation, and caller computer.
      4771 - Kerberos pre-authentication failed (bad password)
      4776 - NTLM credential validation
      4740 - Account locked out
      4625 - Failed logon (logged on the computer where it was attempted)
.PARAMETER Hours
    How far back to search. Default 24.
.PARAMETER OutFile
    Optional CSV path to export the results.
.EXAMPLE
    .\Get-FailedLogons.ps1 -Hours 48 -OutFile C:\FailedLogons.csv
.NOTES
    Run in an elevated PowerShell session on the domain controller.
    Requires failure auditing for Credential Validation and Kerberos
    Authentication Service (Advanced Audit Policy > Account Logon).
    Developed with AI assistance (Claude).
#>
param(
    [int]$Hours = 24,
    [string]$OutFile
)

$start = (Get-Date).AddHours(-$Hours)

$results = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4625, 4771, 4776, 4740
    StartTime = $start
} -ErrorAction SilentlyContinue | ForEach-Object {
    # Read each event's data fields by name instead of by position
    $d = @{}
    ([xml]$_.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{
        Time        = $_.TimeCreated
        Id          = $_.Id
        User        = $d['TargetUserName']
        Source      = $d['IpAddress']
        Workstation = $d['Workstation']
        Caller      = $d['TargetDomainName']
    }
} | Sort-Object Time

$results | Format-Table -AutoSize
if ($OutFile) { $results | Export-Csv $OutFile -NoTypeInformation }
