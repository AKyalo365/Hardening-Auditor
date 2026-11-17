<#
.SYNOPSIS
    Windows Hardening Auditor — Module 2 (Windows/Linux Hardening Auditor)

.DESCRIPTION
    Audits a Windows host against a CIS-style hardening baseline (UAC,
    firewall, local account privileges, registry security settings, patch
    status, RDP/SMB exposure) and produces a scored, severity-ranked HTML
    report plus a machine-readable JSON file.

    Checks degrade gracefully: if a cmdlet or feature isn't available
    (e.g. Windows Home, non-domain machine, running without admin rights),
    the check is marked "Info" with an explanation instead of throwing.

.PARAMETER OutputDir
    Folder to write the JSON and HTML report into. Created if missing.

.EXAMPLE
    # Run from an elevated PowerShell prompt for full coverage:
    .\Audit-WindowsHardening.ps1 -OutputDir .\reports
#>

[CmdletBinding()]
param(
    [string]$OutputDir = ".\reports"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$timestamp   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$fileStamp   = (Get-Date).ToString("yyyyMMdd-HHmmss")
$hostLabel   = $env:COMPUTERNAME
$jsonOut     = Join-Path $OutputDir "windows-hardening-$fileStamp.json"
$htmlOut     = Join-Path $OutputDir "windows-hardening-$fileStamp.html"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# ---------------------------------------------------------------------------
# Check registry
# ---------------------------------------------------------------------------
$Checks = New-Object System.Collections.Generic.List[PSObject]

function Add-Check {
    param(
        [string]$Id, [string]$Category, [string]$Title, [string]$Severity,
        [string]$Status, [string]$Found, [string]$Expected, [string]$Remediation, [string]$CisRef
    )
    $Checks.Add([PSCustomObject]@{
        id          = $Id
        category    = $Category
        title       = $Title
        severity    = $Severity
        status      = $Status
        found       = $Found
        expected    = $Expected
        remediation = $Remediation
        cis_ref     = $CisRef
    }) | Out-Null
}

function Get-RegValue {
    param([string]$Path, [string]$Name, $Default = $null)
    try {
        if (Test-Path $Path) {
            $v = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
            return $v.$Name
        }
    } catch { }
    return $Default
}

# ---------------------------------------------------------------------------
# 1. UAC (CIS 2.3.17 / 18.9.x)
# ---------------------------------------------------------------------------
function Check-UAC {
    $polPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $enableLUA = Get-RegValue -Path $polPath -Name "EnableLUA" -Default $null
    $consentPromptAdmin = Get-RegValue -Path $polPath -Name "ConsentPromptBehaviorAdmin" -Default $null

    if ($null -eq $enableLUA) {
        Add-Check -Id "UAC-01" -Category "Access Control" -Title "User Account Control (UAC) enabled" -Severity "Critical" `
            -Status "INFO" -Found "registry value unreadable" -Expected "EnableLUA = 1" `
            -Remediation "Re-run elevated, or verify via 'Control Panel > User Accounts > Change UAC settings'." -CisRef "CIS 2.3.17.1"
    } elseif ($enableLUA -eq 1) {
        Add-Check -Id "UAC-01" -Category "Access Control" -Title "User Account Control (UAC) enabled" -Severity "Critical" `
            -Status "PASS" -Found "EnableLUA = 1" -Expected "1" -Remediation "N/A" -CisRef "CIS 2.3.17.1"
    } else {
        Add-Check -Id "UAC-01" -Category "Access Control" -Title "User Account Control (UAC) enabled" -Severity "Critical" `
            -Status "FAIL" -Found "EnableLUA = $enableLUA" -Expected "1" `
            -Remediation "Set HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA to 1 and reboot, or re-enable via Control Panel." -CisRef "CIS 2.3.17.1"
    }

    if ($null -ne $consentPromptAdmin) {
        if ([int]$consentPromptAdmin -ge 2) {
            Add-Check -Id "UAC-02" -Category "Access Control" -Title "UAC prompts admins for consent on elevation" -Severity "High" `
                -Status "PASS" -Found "ConsentPromptBehaviorAdmin = $consentPromptAdmin" -Expected ">= 2" -Remediation "N/A" -CisRef "CIS 2.3.17.2"
        } else {
            Add-Check -Id "UAC-02" -Category "Access Control" -Title "UAC prompts admins for consent on elevation" -Severity "High" `
                -Status "FAIL" -Found "ConsentPromptBehaviorAdmin = $consentPromptAdmin" -Expected ">= 2" `
                -Remediation "Set ConsentPromptBehaviorAdmin to 2 ('Prompt for consent on the secure desktop')." -CisRef "CIS 2.3.17.2"
        }
    }
}

# ---------------------------------------------------------------------------
# 2. Windows Firewall (CIS 9.x)
# ---------------------------------------------------------------------------
function Check-Firewall {
    try {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop
        foreach ($p in $profiles) {
            $id = "FW-$($p.Name)"
            if ($p.Enabled) {
                Add-Check -Id $id -Category "Network" -Title "Windows Firewall enabled — $($p.Name) profile" -Severity "Critical" `
                    -Status "PASS" -Found "Enabled" -Expected "Enabled" -Remediation "N/A" -CisRef "CIS 9.1/9.2/9.3"
            } else {
                Add-Check -Id $id -Category "Network" -Title "Windows Firewall enabled — $($p.Name) profile" -Severity "Critical" `
                    -Status "FAIL" -Found "Disabled" -Expected "Enabled" `
                    -Remediation "Run: Set-NetFirewallProfile -Profile $($p.Name) -Enabled True" -CisRef "CIS 9.1/9.2/9.3"
            }
        }
    } catch {
        Add-Check -Id "FW-01" -Category "Network" -Title "Windows Firewall status" -Severity "Critical" `
            -Status "INFO" -Found "Get-NetFirewallProfile unavailable" -Expected "All profiles enabled" `
            -Remediation "Check manually via 'wf.msc' or 'netsh advfirewall show allprofiles'." -CisRef "CIS 9.1"
    }
}

# ---------------------------------------------------------------------------
# 3. Local account privileges (CIS 2.3.1.x, 5.x)
# ---------------------------------------------------------------------------
function Check-Accounts {
    try {
        $guest = Get-LocalUser -Name "Guest" -ErrorAction Stop
        if (-not $guest.Enabled) {
            Add-Check -Id "ACC-01" -Category "Account Security" -Title "Built-in Guest account disabled" -Severity "Critical" `
                -Status "PASS" -Found "Disabled" -Expected "Disabled" -Remediation "N/A" -CisRef "CIS 2.3.1.2"
        } else {
            Add-Check -Id "ACC-01" -Category "Account Security" -Title "Built-in Guest account disabled" -Severity "Critical" `
                -Status "FAIL" -Found "Enabled" -Expected "Disabled" `
                -Remediation "Run: Disable-LocalUser -Name 'Guest'" -CisRef "CIS 2.3.1.2"
        }
    } catch {
        Add-Check -Id "ACC-01" -Category "Account Security" -Title "Built-in Guest account disabled" -Severity "Critical" `
            -Status "INFO" -Found "unable to query local Guest account" -Expected "Disabled" `
            -Remediation "Check manually via 'lusrmgr.msc' (not available on domain controllers)." -CisRef "CIS 2.3.1.2"
    }

    try {
        $admin = Get-LocalUser -Name "Administrator" -ErrorAction Stop
        if ($admin.Enabled) {
            Add-Check -Id "ACC-02" -Category "Account Security" -Title "Built-in Administrator account disabled or renamed" -Severity "High" `
                -Status "WARN" -Found "Enabled, name='Administrator'" -Expected "Disabled, or renamed from default" `
                -Remediation "Disable it (Disable-LocalUser -Name 'Administrator') if a named admin account exists, or rename it via local security policy." -CisRef "CIS 2.3.1.5 / 2.3.1.6"
        } else {
            Add-Check -Id "ACC-02" -Category "Account Security" -Title "Built-in Administrator account disabled or renamed" -Severity "High" `
                -Status "PASS" -Found "Disabled" -Expected "Disabled or renamed" -Remediation "N/A" -CisRef "CIS 2.3.1.5"
        }
    } catch {
        Add-Check -Id "ACC-02" -Category "Account Security" -Title "Built-in Administrator account disabled or renamed" -Severity "High" `
            -Status "INFO" -Found "unable to query" -Expected "Disabled or renamed" -Remediation "Check manually." -CisRef "CIS 2.3.1.5"
    }

    try {
        $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
        $count = ($admins | Measure-Object).Count
        $names = ($admins | ForEach-Object { $_.Name }) -join ", "
        if ($count -le 3) {
            Add-Check -Id "ACC-03" -Category "Account Security" -Title "Local Administrators group membership is minimal" -Severity "Medium" `
                -Status "PASS" -Found "$count member(s): $names" -Expected "<= 3 (heuristic)" -Remediation "N/A" -CisRef "CIS 5.x"
        } else {
            Add-Check -Id "ACC-03" -Category "Account Security" -Title "Local Administrators group membership is minimal" -Severity "Medium" `
                -Status "WARN" -Found "$count member(s): $names" -Expected "<= 3 (heuristic)" `
                -Remediation "Review membership with 'Get-LocalGroupMember Administrators' and remove accounts that don't need standing admin rights." -CisRef "CIS 5.x"
        }
    } catch {
        Add-Check -Id "ACC-03" -Category "Account Security" -Title "Local Administrators group membership is minimal" -Severity "Medium" `
            -Status "INFO" -Found "unable to enumerate group" -Expected "<= 3 members" -Remediation "Check manually via lusrmgr.msc." -CisRef "CIS 5.x"
    }
}

# ---------------------------------------------------------------------------
# 4. Password / lockout policy (CIS 1.1.x, 1.2.x) via 'net accounts'
# ---------------------------------------------------------------------------
function Check-PasswordPolicy {
    try {
        $netOut = net accounts 2>$null
        $minLenLine = $netOut | Select-String "Minimum password length"
        $lockoutLine = $netOut | Select-String "Lockout threshold"
        $maxAgeLine = $netOut | Select-String "Maximum password age"

        $minLen = 0
        if ($minLenLine -match "(\d+)") { $minLen = [int]$Matches[1] }
        if ($minLen -ge 14) {
            Add-Check -Id "PW-01" -Category "Password Policy" -Title "Minimum password length >= 14" -Severity "High" `
                -Status "PASS" -Found "$minLen characters" -Expected ">= 14" -Remediation "N/A" -CisRef "CIS 1.1.4"
        } else {
            Add-Check -Id "PW-01" -Category "Password Policy" -Title "Minimum password length >= 14" -Severity "High" `
                -Status "FAIL" -Found "$minLen characters" -Expected ">= 14" `
                -Remediation "Run: net accounts /minpwlen:14  (or set via Local Security Policy > Account Policies)." -CisRef "CIS 1.1.4"
        }

        $lockoutText = "$lockoutLine"
        if ($lockoutText -match "(\d+)") {
            $threshold = [int]$Matches[1]
            if ($threshold -ge 1 -and $threshold -le 10) {
                Add-Check -Id "PW-02" -Category "Password Policy" -Title "Account lockout threshold configured (1-10 attempts)" -Severity "High" `
                    -Status "PASS" -Found "$threshold attempts" -Expected "1-10" -Remediation "N/A" -CisRef "CIS 1.2.2"
            } else {
                Add-Check -Id "PW-02" -Category "Password Policy" -Title "Account lockout threshold configured (1-10 attempts)" -Severity "High" `
                    -Status "WARN" -Found "$threshold attempts" -Expected "1-10" `
                    -Remediation "Run: net accounts /lockoutthreshold:5" -CisRef "CIS 1.2.2"
            }
        } else {
            Add-Check -Id "PW-02" -Category "Password Policy" -Title "Account lockout threshold configured (1-10 attempts)" -Severity "High" `
                -Status "FAIL" -Found "no lockout threshold set (Never)" -Expected "1-10" `
                -Remediation "Run: net accounts /lockoutthreshold:5 — an unlimited threshold allows unlimited password guessing." -CisRef "CIS 1.2.2"
        }
    } catch {
        Add-Check -Id "PW-01" -Category "Password Policy" -Title "Password and lockout policy" -Severity "High" `
            -Status "INFO" -Found "'net accounts' unavailable" -Expected "N/A" -Remediation "Check via Local Security Policy (secpol.msc)." -CisRef "CIS 1.1/1.2"
    }
}

# ---------------------------------------------------------------------------
# 5. RDP exposure (CIS 18.9.65 / 18.10.x)
# ---------------------------------------------------------------------------
function Check-RDP {
    $rdpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
    $denyRdp = Get-RegValue -Path $rdpPath -Name "fDenyTSConnections" -Default $null
    $wsPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
    $nla = Get-RegValue -Path $wsPath -Name "UserAuthentication" -Default $null

    if ($denyRdp -eq 1 -or $null -eq $denyRdp) {
        Add-Check -Id "RDP-01" -Category "Remote Access" -Title "Remote Desktop disabled unless required" -Severity "Medium" `
            -Status "PASS" -Found "RDP disabled (or default-off)" -Expected "Disabled unless business need exists" -Remediation "N/A" -CisRef "CIS 18.9.65"
    } else {
        Add-Check -Id "RDP-01" -Category "Remote Access" -Title "Remote Desktop disabled unless required" -Severity "Medium" `
            -Status "WARN" -Found "RDP enabled" -Expected "Disabled unless business need exists" `
            -Remediation "If RDP isn't needed, disable it via System Properties > Remote, or set fDenyTSConnections=1. If needed, restrict by firewall/VPN." -CisRef "CIS 18.9.65"

        if ($nla -eq 1) {
            Add-Check -Id "RDP-02" -Category "Remote Access" -Title "RDP requires Network Level Authentication (NLA)" -Severity "High" `
                -Status "PASS" -Found "UserAuthentication = 1" -Expected "1" -Remediation "N/A" -CisRef "CIS 18.9.65.3"
        } else {
            Add-Check -Id "RDP-02" -Category "Remote Access" -Title "RDP requires Network Level Authentication (NLA)" -Severity "High" `
                -Status "FAIL" -Found "UserAuthentication = $nla" -Expected "1" `
                -Remediation "Enable NLA via System Properties > Remote > 'Allow connections only from computers running Remote Desktop with NLA'." -CisRef "CIS 18.9.65.3"
        }
    }
}

# ---------------------------------------------------------------------------
# 6. SMBv1 (CIS 18.3.x — legacy protocol, EternalBlue vector)
# ---------------------------------------------------------------------------
function Check-SMB1 {
    try {
        $smb1 = (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol
        if ($smb1 -eq $false) {
            Add-Check -Id "SMB-01" -Category "Network" -Title "SMBv1 protocol disabled" -Severity "Critical" `
                -Status "PASS" -Found "EnableSMB1Protocol = False" -Expected "False" -Remediation "N/A" -CisRef "CIS 18.3.x (MS17-010 vector)"
        } else {
            Add-Check -Id "SMB-01" -Category "Network" -Title "SMBv1 protocol disabled" -Severity "Critical" `
                -Status "FAIL" -Found "EnableSMB1Protocol = True" -Expected "False" `
                -Remediation "Run: Set-SmbServerConfiguration -EnableSMB1Protocol `$false  (also remove the SMB1Protocol Windows feature)." -CisRef "CIS 18.3.x (MS17-010 vector)"
        }
    } catch {
        Add-Check -Id "SMB-01" -Category "Network" -Title "SMBv1 protocol disabled" -Severity "Critical" `
            -Status "INFO" -Found "Get-SmbServerConfiguration unavailable" -Expected "SMBv1 disabled" `
            -Remediation "Check via: Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol" -CisRef "CIS 18.3.x"
    }
}

# ---------------------------------------------------------------------------
# 7. Antivirus / Defender status (CIS 18.9.47)
# ---------------------------------------------------------------------------
function Check-Defender {
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        if ($mp.AntivirusEnabled -and $mp.RealTimeProtectionEnabled) {
            Add-Check -Id "AV-01" -Category "Endpoint Protection" -Title "Real-time antivirus protection active" -Severity "Critical" `
                -Status "PASS" -Found "Defender enabled, real-time protection on" -Expected "Enabled" -Remediation "N/A" -CisRef "CIS 18.9.47"
        } else {
            Add-Check -Id "AV-01" -Category "Endpoint Protection" -Title "Real-time antivirus protection active" -Severity "Critical" `
                -Status "FAIL" -Found "AntivirusEnabled=$($mp.AntivirusEnabled), RealTime=$($mp.RealTimeProtectionEnabled)" -Expected "Both True" `
                -Remediation "Enable Windows Defender real-time protection, or confirm a third-party AV is installed and active." -CisRef "CIS 18.9.47"
        }
        $sigAge = $mp.AntivirusSignatureAge
        if ($null -ne $sigAge -and $sigAge -le 7) {
            Add-Check -Id "AV-02" -Category "Endpoint Protection" -Title "Antivirus signatures up to date (<= 7 days old)" -Severity "High" `
                -Status "PASS" -Found "$sigAge day(s) old" -Expected "<= 7 days" -Remediation "N/A" -CisRef "CIS 18.9.47"
        } else {
            Add-Check -Id "AV-02" -Category "Endpoint Protection" -Title "Antivirus signatures up to date (<= 7 days old)" -Severity "High" `
                -Status "WARN" -Found "$sigAge day(s) old" -Expected "<= 7 days" `
                -Remediation "Run: Update-MpSignature" -CisRef "CIS 18.9.47"
        }
    } catch {
        Add-Check -Id "AV-01" -Category "Endpoint Protection" -Title "Real-time antivirus protection active" -Severity "Critical" `
            -Status "INFO" -Found "Get-MpComputerStatus unavailable (third-party AV or restricted access)" -Expected "AV active" `
            -Remediation "Verify third-party antivirus is installed, running, and up to date." -CisRef "CIS 18.9.47"
    }
}

# ---------------------------------------------------------------------------
# 8. Windows Update status (CIS 18.9.x)
# ---------------------------------------------------------------------------
function Check-WindowsUpdate {
    try {
        $wuService = Get-Service -Name wuauserv -ErrorAction Stop
        if ($wuService.StartType -eq "Disabled") {
            Add-Check -Id "UPD-01" -Category "Patch Management" -Title "Windows Update service not disabled" -Severity "Critical" `
                -Status "FAIL" -Found "wuauserv StartType = Disabled" -Expected "Not Disabled" `
                -Remediation "Run: Set-Service -Name wuauserv -StartupType Manual (Windows Update manages its own triggers)." -CisRef "CIS 18.9.x"
        } else {
            Add-Check -Id "UPD-01" -Category "Patch Management" -Title "Windows Update service not disabled" -Severity "Critical" `
                -Status "PASS" -Found "wuauserv StartType = $($wuService.StartType)" -Expected "Not Disabled" -Remediation "N/A" -CisRef "CIS 18.9.x"
        }
    } catch {
        Add-Check -Id "UPD-01" -Category "Patch Management" -Title "Windows Update service not disabled" -Severity "Critical" `
            -Status "INFO" -Found "unable to query wuauserv" -Expected "N/A" -Remediation "Check manually via services.msc." -CisRef "CIS 18.9.x"
    }

    try {
        $hotfixes = Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending
        $latest = $hotfixes | Select-Object -First 1
        if ($latest -and $latest.InstalledOn) {
            $daysSince = (New-TimeSpan -Start $latest.InstalledOn -End (Get-Date)).Days
            if ($daysSince -le 45) {
                Add-Check -Id "UPD-02" -Category "Patch Management" -Title "Recent security patches applied (<= 45 days)" -Severity "High" `
                    -Status "PASS" -Found "Last update $daysSince day(s) ago" -Expected "<= 45 days" -Remediation "N/A" -CisRef "CIS 18.9.x"
            } else {
                Add-Check -Id "UPD-02" -Category "Patch Management" -Title "Recent security patches applied (<= 45 days)" -Severity "High" `
                    -Status "WARN" -Found "Last update $daysSince day(s) ago" -Expected "<= 45 days" `
                    -Remediation "Open Settings > Windows Update and install pending updates. Consider enabling automatic updates." -CisRef "CIS 18.9.x"
            }
        } else {
            Add-Check -Id "UPD-02" -Category "Patch Management" -Title "Recent security patches applied (<= 45 days)" -Severity "High" `
                -Status "INFO" -Found "no hotfix install dates available" -Expected "<= 45 days" -Remediation "Check update history in Settings > Windows Update." -CisRef "CIS 18.9.x"
        }
    } catch {
        Add-Check -Id "UPD-02" -Category "Patch Management" -Title "Recent security patches applied (<= 45 days)" -Severity "High" `
            -Status "INFO" -Found "Get-HotFix unavailable" -Expected "<= 45 days" -Remediation "Check update history in Settings > Windows Update." -CisRef "CIS 18.9.x"
    }
}

# ---------------------------------------------------------------------------
# 9. Registry hardening: AutoAdminLogon, LLMNR, screen lock (CIS 18.x, 9.x)
# ---------------------------------------------------------------------------
function Check-RegistryHardening {
    $winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $autoLogon = Get-RegValue -Path $winlogonPath -Name "AutoAdminLogon" -Default "0"
    if ("$autoLogon" -eq "0" -or [string]::IsNullOrEmpty($autoLogon)) {
        Add-Check -Id "REG-01" -Category "Registry Hardening" -Title "Automatic admin logon disabled" -Severity "Critical" `
            -Status "PASS" -Found "AutoAdminLogon = $autoLogon" -Expected "0" -Remediation "N/A" -CisRef "CIS 18.9.x"
    } else {
        Add-Check -Id "REG-01" -Category "Registry Hardening" -Title "Automatic admin logon disabled" -Severity "Critical" `
            -Status "FAIL" -Found "AutoAdminLogon = $autoLogon" -Expected "0" `
            -Remediation "Set HKLM:\...\Winlogon\AutoAdminLogon to 0 and remove any stored DefaultPassword value. Auto-logon stores a plaintext credential in the registry." -CisRef "CIS 18.9.x"
    }

    $dnsClientPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    $llmnr = Get-RegValue -Path $dnsClientPath -Name "EnableMulticast" -Default $null
    if ($llmnr -eq 0) {
        Add-Check -Id "REG-02" -Category "Registry Hardening" -Title "LLMNR disabled (reduces spoofing/relay attack surface)" -Severity "Medium" `
            -Status "PASS" -Found "EnableMulticast = 0" -Expected "0" -Remediation "N/A" -CisRef "CIS 18.5.4.2"
    } else {
        Add-Check -Id "REG-02" -Category "Registry Hardening" -Title "LLMNR disabled (reduces spoofing/relay attack surface)" -Severity "Medium" `
            -Status "WARN" -Found "EnableMulticast = $llmnr (not explicitly disabled)" -Expected "0" `
            -Remediation "Via Group Policy: Computer Config > Admin Templates > Network > DNS Client > 'Turn off multicast name resolution' = Enabled." -CisRef "CIS 18.5.4.2"
    }

    try {
        $screenSaveActive = (Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive" -ErrorAction Stop).ScreenSaveActive
        $screenSaverSecure = (Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -ErrorAction Stop).ScreenSaverIsSecure
        if ($screenSaveActive -eq "1" -and $screenSaverSecure -eq "1") {
            Add-Check -Id "REG-03" -Category "Registry Hardening" -Title "Password-protected screen lock enabled" -Severity "Medium" `
                -Status "PASS" -Found "ScreenSaveActive=1, Secure=1" -Expected "Both 1" -Remediation "N/A" -CisRef "CIS 18.x"
        } else {
            Add-Check -Id "REG-03" -Category "Registry Hardening" -Title "Password-protected screen lock enabled" -Severity "Medium" `
                -Status "WARN" -Found "ScreenSaveActive=$screenSaveActive, Secure=$screenSaverSecure" -Expected "Both 1" `
                -Remediation "Enable 'On resume, display logon screen' in Settings > Personalization > Lock screen > Screen saver settings." -CisRef "CIS 18.x"
        }
    } catch {
        Add-Check -Id "REG-03" -Category "Registry Hardening" -Title "Password-protected screen lock enabled" -Severity "Medium" `
            -Status "INFO" -Found "per-user setting not queryable in this context" -Expected "Enabled" `
            -Remediation "Verify in Settings > Personalization > Lock screen for each user account." -CisRef "CIS 18.x"
    }
}

# ---------------------------------------------------------------------------
# 10. PowerShell execution policy & logging (CIS 18.9.100.x)
# ---------------------------------------------------------------------------
function Check-PowerShellPolicy {
    try {
        $ep = Get-ExecutionPolicy -Scope LocalMachine -ErrorAction Stop
        if ($ep -in @("Restricted", "AllSigned", "RemoteSigned")) {
            Add-Check -Id "PS-01" -Category "System Hardening" -Title "PowerShell execution policy restricts unsigned remote scripts" -Severity "Medium" `
                -Status "PASS" -Found "$ep" -Expected "Restricted / AllSigned / RemoteSigned" -Remediation "N/A" -CisRef "CIS 18.9.100"
        } else {
            Add-Check -Id "PS-01" -Category "System Hardening" -Title "PowerShell execution policy restricts unsigned remote scripts" -Severity "Medium" `
                -Status "WARN" -Found "$ep" -Expected "Restricted / AllSigned / RemoteSigned" `
                -Remediation "Run: Set-ExecutionPolicy RemoteSigned -Scope LocalMachine" -CisRef "CIS 18.9.100"
        }
    } catch {
        Add-Check -Id "PS-01" -Category "System Hardening" -Title "PowerShell execution policy restricts unsigned remote scripts" -Severity "Medium" `
            -Status "INFO" -Found "unable to query" -Expected "N/A" -Remediation "Check manually via Get-ExecutionPolicy -List." -CisRef "CIS 18.9.100"
    }

    $scriptBlockPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    $sbLogging = Get-RegValue -Path $scriptBlockPath -Name "EnableScriptBlockLogging" -Default $null
    if ($sbLogging -eq 1) {
        Add-Check -Id "PS-02" -Category "System Hardening" -Title "PowerShell Script Block Logging enabled" -Severity "Low" `
            -Status "PASS" -Found "EnableScriptBlockLogging = 1" -Expected "1" -Remediation "N/A" -CisRef "CIS 18.9.100.1"
    } else {
        Add-Check -Id "PS-02" -Category "System Hardening" -Title "PowerShell Script Block Logging enabled" -Severity "Low" `
            -Status "WARN" -Found "not enabled" -Expected "1" `
            -Remediation "Enable via Group Policy: Admin Templates > Windows Components > PowerShell > Turn on PowerShell Script Block Logging. Useful for incident response." -CisRef "CIS 18.9.100.1"
    }
}

# ---------------------------------------------------------------------------
# Run all checks
# ---------------------------------------------------------------------------
Check-UAC
Check-Firewall
Check-Accounts
Check-PasswordPolicy
Check-RDP
Check-SMB1
Check-Defender
Check-WindowsUpdate
Check-RegistryHardening
Check-PowerShellPolicy

# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------
function Get-SeverityWeight {
    param([string]$Severity)
    switch ($Severity) {
        "Critical" { 10 }
        "High"     { 7 }
        "Medium"   { 4 }
        "Low"      { 2 }
        default    { 1 }
    }
}

$totalWeight = 0
$earnedWeight = 0
$passN = 0; $failN = 0; $warnN = 0; $infoN = 0

foreach ($c in $Checks) {
    $w = Get-SeverityWeight -Severity $c.severity
    switch ($c.status) {
        "PASS" { $totalWeight += $w; $earnedWeight += $w; $passN++ }
        "FAIL" { $totalWeight += $w; $failN++ }
        "WARN" { $totalWeight += $w; $earnedWeight += [math]::Floor($w / 2); $warnN++ }
        "INFO" { $infoN++ }
    }
}

$score = 100
if ($totalWeight -gt 0) {
    $score = [math]::Round(($earnedWeight * 100) / $totalWeight)
}

$grade = "F"
if ($score -ge 90) { $grade = "A" }
elseif ($score -ge 80) { $grade = "B" }
elseif ($score -ge 70) { $grade = "C" }
elseif ($score -ge 60) { $grade = "D" }

# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------
$report = [PSCustomObject]@{
    scan_type    = "windows"
    host         = $hostLabel
    timestamp_utc = $timestamp
    ran_as_root  = [bool]$isAdmin
    score        = $score
    grade        = $grade
    summary      = [PSCustomObject]@{ pass = $passN; fail = $failN; warn = $warnN; info = $infoN }
    checks       = $Checks
}

$report | ConvertTo-Json -Depth 6 | Out-File -FilePath $jsonOut -Encoding utf8

# ---------------------------------------------------------------------------
# HTML output (same visual template as the Linux script, generated natively
# so this .ps1 has no dependency on bash/WSL being present)
# ---------------------------------------------------------------------------
$jsonForHtml = $report | ConvertTo-Json -Depth 6
$title = "Windows Hardening Report - $hostLabel"

$htmlTemplate = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>__TITLE__</title>
<style>
  :root {
    --pass: #1a7f37; --fail: #cf222e; --warn: #9a6700; --info: #57606a;
    --bg: #f6f8fa; --card: #ffffff; --border: #d0d7de; --text: #24292f; --muted: #57606a;
    --crit: #a40e26; --high: #cf222e; --med: #9a6700; --low: #57606a;
  }
  * { box-sizing: border-box; }
  body { font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 0 0 60px 0; }
  header { background: #0d1117; color: #fff; padding: 28px 32px; }
  header h1 { margin: 0 0 4px 0; font-size: 22px; }
  header .meta { color: #9da7b3; font-size: 13px; }
  .wrap { max-width: 1000px; margin: 0 auto; padding: 24px 20px; }
  .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 24px; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 18px; text-align: center; }
  .card .num { font-size: 30px; font-weight: 700; }
  .card .label { color: var(--muted); font-size: 13px; margin-top: 4px; }
  .score-card { grid-column: span 2; display: flex; align-items: center; justify-content: center; gap: 20px; }
  .score-ring { width: 92px; height: 92px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 26px; font-weight: 700; color: #fff; }
  .grade-A { background: #1a7f37; } .grade-B { background: #4c9a2a; } .grade-C { background: #9a6700; }
  .grade-D { background: #bc4c00; } .grade-F { background: #cf222e; }
  .score-detail { text-align: left; }
  .score-detail .big { font-size: 15px; font-weight: 600; }
  .score-detail .sub { color: var(--muted); font-size: 13px; margin-top: 2px; }
  h2.section { font-size: 15px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--muted); margin: 32px 0 10px 0; border-bottom: 1px solid var(--border); padding-bottom: 6px; }
  table { width: 100%; border-collapse: collapse; background: var(--card); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
  th, td { text-align: left; padding: 10px 12px; font-size: 13px; border-bottom: 1px solid var(--border); vertical-align: top; }
  th { background: #f6f8fa; font-size: 11px; text-transform: uppercase; color: var(--muted); letter-spacing: 0.03em; }
  tr:last-child td { border-bottom: none; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; color: #fff; white-space: nowrap; }
  .badge-PASS { background: var(--pass); } .badge-FAIL { background: var(--fail); }
  .badge-WARN { background: var(--warn); } .badge-INFO { background: var(--info); }
  .sev { font-weight: 600; font-size: 12px; }
  .sev-Critical { color: var(--crit); } .sev-High { color: var(--high); }
  .sev-Medium { color: var(--med); } .sev-Low { color: var(--low); }
  .remediation { color: var(--muted); font-style: italic; }
  .cis { color: var(--muted); font-size: 11px; white-space: nowrap; }
  .filters { margin: 14px 0; display: flex; gap: 8px; flex-wrap: wrap; }
  .filters button { border: 1px solid var(--border); background: #fff; padding: 6px 12px; border-radius: 16px; font-size: 12px; cursor: pointer; }
  .filters button.active { background: #0d1117; color: #fff; border-color: #0d1117; }
  footer { text-align: center; color: var(--muted); font-size: 12px; margin-top: 40px; }
  @media print {
    header { background: #0d1117 !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    .filters { display: none; }
    body { padding: 0; }
  }
</style>
</head>
<body>
<header>
  <h1>__TITLE__</h1>
  <div class="meta" id="meta-line">Loading...</div>
</header>
<div class="wrap">
  <div class="summary-grid" id="summary-grid"></div>
  <div class="filters" id="filters"></div>
  <div id="categories"></div>
</div>
<footer>Generated by the Windows/Linux Hardening Auditor - mapped to CIS-style benchmark controls. Review remediation notes before making changes in a live environment.</footer>

<script type="application/json" id="report-data">
__JSON__
</script>
<script>
const data = JSON.parse(document.getElementById('report-data').textContent);

document.getElementById('meta-line').textContent =
  `Host: ${data.host}  -  Scanned: ${data.timestamp_utc}${data.ran_as_root === false ? '  -  NOTE: not run elevated - some checks limited' : ''}`;

const gradeClass = 'grade-' + data.grade;
const summaryGrid = document.getElementById('summary-grid');
summaryGrid.innerHTML = `
  <div class="card score-card">
    <div class="score-ring ${gradeClass}">${data.grade}</div>
    <div class="score-detail">
      <div class="big">${data.score} / 100 compliance score</div>
      <div class="sub">Weighted by control severity (Critical &gt; High &gt; Medium &gt; Low)</div>
    </div>
  </div>
  <div class="card"><div class="num" style="color:var(--pass)">${data.summary.pass}</div><div class="label">Pass</div></div>
  <div class="card"><div class="num" style="color:var(--fail)">${data.summary.fail}</div><div class="label">Fail</div></div>
  <div class="card"><div class="num" style="color:var(--warn)">${data.summary.warn}</div><div class="label">Warning</div></div>
`;

const categories = [...new Set(data.checks.map(c => c.category))];
const filtersEl = document.getElementById('filters');
const statuses = ['ALL', 'FAIL', 'WARN', 'PASS', 'INFO'];
let activeFilter = 'ALL';

function render() {
  filtersEl.innerHTML = statuses.map(s =>
    `<button data-s="${s}" class="${s===activeFilter?'active':''}">${s === 'ALL' ? 'All checks' : s.charAt(0)+s.slice(1).toLowerCase()}</button>`
  ).join('');
  filtersEl.querySelectorAll('button').forEach(b => b.onclick = () => { activeFilter = b.dataset.s; render(); });

  const catsEl = document.getElementById('categories');
  catsEl.innerHTML = '';
  categories.forEach(cat => {
    const rows = data.checks.filter(c => c.category === cat && (activeFilter === 'ALL' || c.status === activeFilter));
    if (rows.length === 0) return;
    const section = document.createElement('div');
    section.innerHTML = `<h2 class="section">${cat}</h2>`;
    const table = document.createElement('table');
    table.innerHTML = `
      <thead><tr>
        <th>Check</th><th>Severity</th><th>Status</th><th>Found</th><th>Expected</th><th>Remediation</th><th>Ref</th>
      </tr></thead>
      <tbody>
        ${rows.map(c => `
          <tr>
            <td><strong>${c.title}</strong><br><span class="cis">${c.id}</span></td>
            <td><span class="sev sev-${c.severity}">${c.severity}</span></td>
            <td><span class="badge badge-${c.status}">${c.status}</span></td>
            <td>${c.found}</td>
            <td>${c.expected}</td>
            <td class="remediation">${c.status === 'PASS' ? '-' : c.remediation}</td>
            <td class="cis">${c.cis_ref}</td>
          </tr>
        `).join('')}
      </tbody>
    `;
    section.appendChild(table);
    catsEl.appendChild(section);
  });
}
render();
</script>
</body>
</html>
'@

$htmlFinal = $htmlTemplate.Replace('__TITLE__', $title).Replace('__JSON__', $jsonForHtml)
$htmlFinal | Out-File -FilePath $htmlOut -Encoding utf8

# ---------------------------------------------------------------------------
# Console summary
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "Windows hardening audit complete." -ForegroundColor Cyan
Write-Host "  Score: $score / 100 (Grade $grade)"
Write-Host "  Pass: $passN  Fail: $failN  Warn: $warnN  Info: $infoN"
Write-Host "  JSON: $jsonOut"
Write-Host "  HTML: $htmlOut"
if (-not $isAdmin) {
    Write-Host "  NOTE: not running elevated - some checks may be limited or marked Info. Re-run 'as Administrator' for full coverage." -ForegroundColor Yellow
}
