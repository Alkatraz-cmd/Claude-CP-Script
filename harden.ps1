#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CyberPatriot Windows hardening helper (Windows 10/11, Server 2016+).

.DESCRIPTION
    Menu-driven. Every change is shown and confirmed before it is made.
    Fill in users.txt and admins.txt (from the image README) before running.

    DO THE FORENSICS QUESTIONS FIRST. This script never deletes files, but
    removing users/services can destroy the evidence a question asks about.

.PARAMETER AuditOnly
    Report what is wrong, change nothing.

.PARAMETER Yes
    Auto-accept the safe changes (policies, firewall, registry). Anything
    that could break a README requirement (users, services, features,
    Remote Desktop) still asks.

.PARAMETER All
    Run every section in order instead of showing the menu.

.PARAMETER Library
    Only define the functions (used by gui.ps1). Runs nothing.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\harden.ps1 -AuditOnly
#>
[CmdletBinding()]
param(
    [switch]$AuditOnly,
    [switch]$Yes,
    [switch]$All,
    [switch]$Library
)

$ErrorActionPreference = 'Continue'
$ScriptDir = $PSScriptRoot
$Stamp     = Get-Date -Format 'yyyyMMdd-HHmmss'
$LogDir    = Join-Path $ScriptDir 'logs'
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir | Out-Null }
$ReportFile = Join-Path $LogDir "report-windows-$Stamp.txt"

# ---------------------------------------------------------------- helpers ---

function Section($text) { Write-Host "`n=== $text ===" -ForegroundColor Cyan }
function Info($text)    { Write-Host "    $text" }
function Good($text)    { Write-Host "[ok] $text" -ForegroundColor Green }
function Warn($text)    { Write-Host "[!!] $text" -ForegroundColor Yellow }
function Bad($text)     { Write-Host "[xx] $text" -ForegroundColor Red }

# Ask before making a change. -Risky changes always ask, even with -Yes.
function Confirm-Change {
    param([string]$Question, [switch]$Risky)
    if ($AuditOnly) { Info "(audit only) skipped: $Question"; return $false }
    if ($Yes -and -not $Risky) { Info "auto-yes: $Question"; return $true }
    $answer = Read-Host "$Question [y/N]"
    return ($answer -match '^(y|yes)$')
}

function Read-List($fileName) {
    $path = Join-Path $ScriptDir $fileName
    if (-not (Test-Path $path)) { return @() }
    $items = Get-Content $path |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -and -not $_.StartsWith('#') }
    return @($items)
}

function Get-RegValue($Path, $Name) {
    try { return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name }
    catch { return $null }
}

function Set-RegValue($Path, $Name, $Value) {
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force
}

function Get-Rid($user) {
    return [int]($user.SID.Value.Split('-')[-1])
}

function Add-Report($title, $lines) {
    $lines = @($lines | Where-Object { $_ })
    Add-Content -Path $ReportFile -Value "", "##### $title ($($lines.Count))"
    if ($lines.Count -eq 0) {
        Add-Content -Path $ReportFile -Value "(none)"
        Good "$title - none found"
    } else {
        Add-Content -Path $ReportFile -Value $lines
        Warn "$title - $($lines.Count) found:"
        $lines | Select-Object -First 15 | ForEach-Object { Info $_ }
        if ($lines.Count -gt 15) { Info "... $($lines.Count - 15) more in the report file" }
    }
}

function Read-NewPassword {
    return (Read-Host '  New password (12+ chars, upper/lower/number/symbol)' -AsSecureString)
}

# ----------------------------------------------------------------- README ---
#
# The image README is turned into three small files that every section reads:
#   admins.txt    authorized administrators
#   users.txt     authorized standard users
#   services.txt  required services, as tags from $ServiceTags below

$ServiceTags = [ordered]@{
    rdp    = 'remote desktop|rdp|terminal services'
    ssh    = 'ssh'
    ftp    = 'ftp|filezilla'
    web    = 'iis|apache|nginx|http|web|world wide'
    smb    = 'samba|smb|file shar|file server'
    dns    = 'dns|bind'
    mail   = 'mail|smtp|postfix|dovecot|exchange|pop3|imap'
    sql    = 'sql|maria|postgres|database'
    print  = 'print|cups'
    telnet = 'telnet'
    snmp   = 'snmp'
    vnc    = 'vnc'
}

function Test-Required($tag) {
    return ((Read-List 'services.txt') -contains $tag)
}

# Pulls users, admins and critical services out of pasted README text.
# It is a best guess - always look over the result before trusting it.
function ConvertFrom-Readme([string]$Text) {
    $admins   = New-Object System.Collections.Generic.List[string]
    $users    = New-Object System.Collections.Generic.List[string]
    $services = New-Object System.Collections.Generic.List[string]
    $unmapped = New-Object System.Collections.Generic.List[string]
    $you  = ''
    $mode = ''
    $gotService = $false

    foreach ($raw in ($Text -split "`r?`n")) {
        $line = ($raw.Trim() -replace '^[-*]+\s*', '')

        if ($line -match '^authorized\s+administrators\s*:?$') { $mode = 'admins'; continue }
        if ($line -match '^authorized\s+users\s*:?$')          { $mode = 'users';  continue }

        $items = @()
        if ($line -match '^critical\s+services') {
            $mode = 'services'; $gotService = $false
            if ($line.Contains(':')) {
                $items = $line.Substring($line.IndexOf(':') + 1).Split(',')
                # The list was on the heading line itself, so the section ends here.
                if ($items | Where-Object { $_.Trim() }) { $mode = '' }
            }
        }
        elseif ($mode -eq 'admins' -or $mode -eq 'users') {
            if (-not $line -or $line -match '^\(?password') { continue }
            if ($line -match '^([A-Za-z][\w.\-]*)(\s*\(you\))?$') {
                $name = $Matches[1]
                if ($Matches[2]) { $you = $name }
                if ($mode -eq 'admins') { $admins.Add($name) } else { $users.Add($name) }
            } else {
                $mode = ''
            }
            continue
        }
        elseif ($mode -eq 'services') {
            if (-not $line) { if ($gotService) { $mode = '' }; continue }
            if ($line.Length -gt 60) { $mode = ''; continue }
            $items = @($line)
        }

        foreach ($item in $items) {
            $item = $item.Trim()
            if (-not $item) { continue }
            $gotService = $true
            if ($item -match '^\(?(none|n/a)\)?\.?$') { continue }
            $tag = $ServiceTags.Keys | Where-Object { $item -match $ServiceTags[$_] } | Select-Object -First 1
            if ($tag) { if (-not $services.Contains($tag)) { $services.Add($tag) } }
            else { $unmapped.Add($item) }
        }
    }

    return [pscustomobject]@{
        Admins   = $admins.ToArray()
        Users    = $users.ToArray()
        Services = $services.ToArray()
        Unmapped = $unmapped.ToArray()
        You      = $you
    }
}

function Show-ReadmeResult($result) {
    if ($result.Admins.Count + $result.Users.Count -eq 0) {
        Bad "Could not find the 'Authorized Administrators' / 'Authorized Users' lists. Type the names in by hand."
    } else {
        Good "Administrators ($($result.Admins.Count)): $($result.Admins -join ', ')"
        Good "Standard users ($($result.Users.Count)): $($result.Users -join ', ')"
    }
    if ($result.Services.Count) { Good "Required services: $($result.Services -join ', ')" }
    else { Info 'Required services: none recognized' }
    foreach ($item in $result.Unmapped) { Warn "Critical service I do not recognize (protect it yourself): $item" }
    if ($result.You -and $result.You -ne $env:USERNAME) {
        Warn "README says you are '$($result.You)' but you are logged in as '$env:USERNAME'."
    }
    Warn 'This is a best guess from the text. Check the lists against the README before running.'
}

function Save-Lists($Admins, $Users, $Services, [string]$ReadmeText) {
    $files = @{
        'admins.txt'   = @('# Authorized ADMINISTRATORS, one per line. Include yourself.') + @($Admins)
        'users.txt'    = @('# Authorized STANDARD users, one per line.') + @($Users)
        'services.txt' = @("# Required services, one tag per line: $($ServiceTags.Keys -join ' ')") + @($Services)
    }
    foreach ($name in $files.Keys) {
        Set-Content -Path (Join-Path $ScriptDir $name) -Value ($files[$name] | Where-Object { $_ })
    }
    if ($ReadmeText) { Set-Content -Path (Join-Path $ScriptDir 'readme.txt') -Value $ReadmeText }
}

# Console version of "paste the README": Notepad is the paste box.
function Import-ReadmeConsole {
    Section 'Read the image README'
    $path = Join-Path $ScriptDir 'readme.txt'
    if (-not (Test-Path $path)) { Set-Content -Path $path -Value '' }
    Info 'Notepad is opening readme.txt. Paste the README text, save, and close Notepad.'
    Start-Process notepad.exe -ArgumentList "`"$path`"" -Wait
    $text = [string](Get-Content $path -Raw)
    $result = ConvertFrom-Readme $text
    Show-ReadmeResult $result
    if ((Read-Host 'Save these to admins.txt / users.txt / services.txt? [y/N]') -match '^(y|yes)$') {
        Save-Lists $result.Admins $result.Users $result.Services
        Good 'Lists saved'
    }
}

# ------------------------------------------------------------------ users ---

function Invoke-Users {
    Section 'Users and groups'
    $authAdmins = @(Read-List 'admins.txt')
    $authUsers  = @(@(Read-List 'users.txt') + $authAdmins | Where-Object { $_ } | Select-Object -Unique)
    $me         = $env:USERNAME

    if (@($authUsers).Count -eq 0) {
        Bad 'users.txt and admins.txt are empty. Fill them in from the README, then re-run this section.'
        return
    }
    if ($authUsers -notcontains $me) {
        Bad "You are logged in as '$me' but that name is not in users.txt/admins.txt."
        Bad 'Fix the lists first so this script cannot remove your own account.'
        return
    }

    $localUsers = Get-LocalUser
    # Built-in accounts are identified by RID so renaming them does not fool us.
    $builtinRids = 500, 501, 503, 504

    # --- unauthorized accounts
    foreach ($u in $localUsers) {
        if ($builtinRids -contains (Get-Rid $u)) { continue }
        if ($authUsers -contains $u.Name) { continue }
        Warn "Unauthorized user: $($u.Name) (enabled: $($u.Enabled))"
        if (Confirm-Change "  Remove user '$($u.Name)'? (their C:\Users folder is kept)" -Risky) {
            Remove-LocalUser -Name $u.Name
            Good "Removed $($u.Name)"
        }
    }

    # --- listed but missing
    foreach ($name in $authUsers) {
        if (-not ($localUsers | Where-Object { $_.Name -eq $name })) {
            Warn "'$name' is in your lists but does not exist. If the README says to add them, create the account by hand."
        }
    }

    # --- Administrators group
    $adminMembers = @()
    try {
        $adminMembers = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop |
            Where-Object { $_.ObjectClass -eq 'User' -and $_.PrincipalSource -eq 'Local' }
    } catch {
        Bad "Could not read the Administrators group ($($_.Exception.Message)). Check it by hand in lusrmgr.msc."
    }
    $adminNames = @($adminMembers | ForEach-Object { $_.Name.Split('\')[-1] })

    foreach ($name in $adminNames) {
        $account = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
        if ($account -and (Get-Rid $account) -eq 500) { continue }
        if ($authAdmins -contains $name) { continue }
        if ($name -eq $me) { Warn "You ($me) are an admin but not in admins.txt - leaving you alone."; continue }
        Warn "Not an authorized administrator: $name"
        if (Confirm-Change "  Remove '$name' from Administrators?" -Risky) {
            Remove-LocalGroupMember -Group 'Administrators' -Member $name
            Good "Demoted $name"
        }
    }
    foreach ($name in $authAdmins) {
        if ($adminNames -contains $name) { continue }
        if (-not (Get-LocalUser -Name $name -ErrorAction SilentlyContinue)) { continue }
        Warn "Authorized administrator is missing from Administrators: $name"
        if (Confirm-Change "  Add '$name' to Administrators?" -Risky) {
            Add-LocalGroupMember -Group 'Administrators' -Member $name
            Good "Promoted $name"
        }
    }

    # --- built-in Guest / Administrator
    foreach ($u in (Get-LocalUser)) {
        $rid = Get-Rid $u
        if ($rid -ne 500 -and $rid -ne 501) { continue }
        if (-not $u.Enabled) { Good "Built-in account '$($u.Name)' is disabled"; continue }
        if ($u.Name -eq $me) { Warn "You are logged in as the built-in '$($u.Name)' - not disabling it."; continue }
        Warn "Built-in account '$($u.Name)' is enabled"
        if (Confirm-Change "  Disable '$($u.Name)'?") {
            Disable-LocalUser -Name $u.Name
            Good "Disabled $($u.Name)"
        }
    }

    # --- password hygiene on the remaining accounts
    $others = Get-LocalUser | Where-Object {
        $_.Enabled -and ($builtinRids -notcontains (Get-Rid $_)) -and $_.Name -ne $me
    }
    foreach ($u in $others) {
        if ($null -eq $u.PasswordExpires) { Warn "$($u.Name): password never expires" }
        if (-not $u.PasswordRequired)     { Warn "$($u.Name): password not required" }
    }
    if ($others -and (Confirm-Change 'Make passwords required and expiring for all other users?')) {
        foreach ($u in $others) {
            Set-LocalUser -Name $u.Name -PasswordNeverExpires $false -UserMayChangePassword $true
            & net user $u.Name /passwordreq:yes | Out-Null
        }
        Good 'Password flags fixed'
    }
    if ($others -and (Confirm-Change "Set one new strong password on every user except you ($me)?" -Risky)) {
        $password = Read-NewPassword
        if (-not $password -or $password.Length -eq 0) {
            Warn 'No password entered - nothing changed'
        } else {
            foreach ($u in $others) {
                try { Set-LocalUser -Name $u.Name -Password $password -ErrorAction Stop; Good "Password set for $($u.Name)" }
                catch { Bad "$($u.Name): $($_.Exception.Message)" }
            }
            Info 'Write that password down. Your own password was not changed.'
        }
    }
}

# -------------------------------------------------------- password policy ---

function Invoke-PasswordPolicy {
    Section 'Password and lockout policy'
    & net accounts | Where-Object { $_ -match '\S' } | ForEach-Object { Info $_ }
    if (-not (Confirm-Change 'Apply policy: min length 10, max age 60, min age 1, history 24, lockout 5 tries / 30 min, complexity on?')) { return }

    & net accounts /minpwlen:10 /maxpwage:60 /minpwage:1 /uniquepw:24 | Out-Null
    & net accounts /lockoutthreshold:5 /lockoutwindow:30 /lockoutduration:30 | Out-Null

    # Complexity and reversible encryption are only reachable through secedit.
    $cfg = Join-Path $env:TEMP "cp-secpol-$Stamp.inf"
    $db  = Join-Path $env:TEMP "cp-secpol-$Stamp.sdb"
    & secedit /export /cfg $cfg /areas SECURITYPOLICY /quiet
    if (-not (Test-Path $cfg)) { Bad 'secedit export failed - set complexity by hand in secpol.msc'; return }

    $text = Get-Content $cfg -Raw
    $wanted = @{ PasswordComplexity = 1; ClearTextPassword = 0 }
    foreach ($key in $wanted.Keys) {
        $line = "$key = $($wanted[$key])"
        if ($text -match "(?m)^$key[ \t]*=") {
            $text = $text -replace "(?m)^$key[ \t]*=[^\r\n]*", $line
        } else {
            $text = $text -replace '(?m)^\[System Access\]', "[System Access]`r`n$line"
        }
    }
    Set-Content -Path $cfg -Value $text -Encoding Unicode
    & secedit /configure /db $db /cfg $cfg /areas SECURITYPOLICY /quiet
    Remove-Item $cfg, $db -Force -ErrorAction SilentlyContinue
    Good 'Password and lockout policy applied'
}

# ----------------------------------------------------------- audit policy ---

function Invoke-AuditPolicy {
    Section 'Audit policy'
    if (Confirm-Change 'Enable success + failure auditing for every category?') {
        & auditpol /set /category:* /success:enable /failure:enable | Out-Null
        Good 'Auditing enabled'
    }
}

# --------------------------------------------------------------- firewall ---

function Invoke-Firewall {
    Section 'Windows Firewall'
    $profiles = Get-NetFirewallProfile
    foreach ($p in $profiles) {
        if ($p.Enabled) { Good "$($p.Name) profile is on" } else { Warn "$($p.Name) profile is OFF" }
    }
    if (Confirm-Change 'Turn on all firewall profiles (block inbound by default, allow outbound)?') {
        Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True `
            -DefaultInboundAction Block -DefaultOutboundAction Allow
        Good 'Firewall enabled on all profiles'
    }
}

# ------------------------------------------------------- security options ---

$SecuritySettings = @(
    @{ P = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System';        N = 'EnableLUA';                  V = 1;   D = 'UAC enabled' }
    @{ P = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System';        N = 'ConsentPromptBehaviorAdmin'; V = 2;   D = 'UAC always prompts admins' }
    @{ P = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System';        N = 'PromptOnSecureDesktop';      V = 1;   D = 'UAC prompt on secure desktop' }
    @{ P = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System';        N = 'DontDisplayLastUserName';    V = 1;   D = 'Do not show last signed-in user' }
    @{ P = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System';        N = 'DisableCAD';                 V = 0;   D = 'Require Ctrl+Alt+Del' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';                             N = 'LimitBlankPasswordUse';      V = 1;   D = 'Blank passwords limited to console' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';                             N = 'RestrictAnonymous';          V = 1;   D = 'No anonymous share enumeration' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';                             N = 'RestrictAnonymousSAM';       V = 1;   D = 'No anonymous SAM enumeration' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';                             N = 'EveryoneIncludesAnonymous';  V = 0;   D = 'Everyone excludes anonymous' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';                             N = 'NoLMHash';                   V = 1;   D = 'Do not store LM hashes' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';                             N = 'LmCompatibilityLevel';       V = 5;   D = 'NTLMv2 only' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters';        N = 'RequireSecuritySignature';   V = 1;   D = 'SMB server signing required' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters';        N = 'SMB1';                       V = 0;   D = 'SMBv1 server off' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters';   N = 'RequireSecuritySignature';   V = 1;   D = 'SMB client signing required' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters';   N = 'EnablePlainTextPassword';    V = 0;   D = 'No plaintext SMB passwords' }
    @{ P = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer';      N = 'NoDriveTypeAutoRun';         V = 255; D = 'AutoPlay off for all drives' }
    @{ P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU';             N = 'NoAutoUpdate';               V = 0;   D = 'Automatic updates on' }
    @{ P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU';             N = 'AUOptions';                  V = 4;   D = 'Updates download and install automatically' }
    @{ P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System';                       N = 'EnableSmartScreen';          V = 1;   D = 'SmartScreen on' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance';               N = 'fAllowToGetHelp';            V = 0;   D = 'Remote Assistance off' }
)

function Invoke-SecurityOptions {
    Section 'Security options (registry)'
    $wrong = @($SecuritySettings | Where-Object { (Get-RegValue $_.P $_.N) -ne $_.V })
    if ($wrong.Count -eq 0) {
        Good 'All security options already set'
    } else {
        foreach ($s in $wrong) { Warn "$($s.D)  [$($s.N) is '$(Get-RegValue $s.P $s.N)', want $($s.V)]" }
        if (Confirm-Change "Fix these $($wrong.Count) settings?") {
            foreach ($s in $wrong) { Set-RegValue $s.P $s.N $s.V }
            Good 'Security options applied'
        }
    }

    # Remote Desktop depends on the README, so it is never automatic.
    $tsKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $rdpOn = (Get-RegValue $tsKey 'fDenyTSConnections') -eq 0
    if (Test-Required 'rdp') {
        if ($rdpOn) {
            Good 'Remote Desktop is on (required by the README)'
        } else {
            Warn 'The README requires Remote Desktop but it is OFF'
            if (Confirm-Change '  Enable Remote Desktop?' -Risky) {
                Set-RegValue $tsKey 'fDenyTSConnections' 0
                Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue
                Good 'Remote Desktop enabled'
            }
        }
        if ((Get-RegValue "$tsKey\WinStations\RDP-Tcp" 'UserAuthentication') -ne 1) {
            if (Confirm-Change '  Require Network Level Authentication for RDP?') {
                Set-RegValue "$tsKey\WinStations\RDP-Tcp" 'UserAuthentication' 1
                Good 'NLA required for RDP'
            }
        }
    } elseif ($rdpOn) {
        Warn 'Remote Desktop is ENABLED'
        if (Confirm-Change '  Disable Remote Desktop? (answer N if the README requires it)' -Risky) {
            Set-RegValue $tsKey 'fDenyTSConnections' 1
            Good 'Remote Desktop disabled'
        } elseif (Confirm-Change '  Keep RDP but require Network Level Authentication?') {
            Set-RegValue "$tsKey\WinStations\RDP-Tcp" 'UserAuthentication' 1
            Good 'NLA required for RDP'
        }
    } else {
        Good 'Remote Desktop is disabled'
    }
}

# --------------------------------------------------------------- services ---

# T = the services.txt tag that protects the service when the README requires it.
$RiskyServices = [ordered]@{
    TlntSvr        = @{ D = 'Telnet server';               T = 'telnet' }
    RemoteRegistry = @{ D = 'Remote Registry';             T = '' }
    SNMP           = @{ D = 'SNMP';                        T = 'snmp' }
    SNMPTRAP       = @{ D = 'SNMP Trap';                   T = 'snmp' }
    SSDPSRV        = @{ D = 'SSDP Discovery';              T = '' }
    upnphost       = @{ D = 'UPnP Device Host';            T = '' }
    ftpsvc         = @{ D = 'Microsoft FTP server';        T = 'ftp' }
    W3SVC          = @{ D = 'IIS web server';              T = 'web' }
    simptcp        = @{ D = 'Simple TCP/IP services';      T = '' }
    SharedAccess   = @{ D = 'Internet Connection Sharing'; T = '' }
    RemoteAccess   = @{ D = 'Routing and Remote Access';   T = '' }
    Fax            = @{ D = 'Fax';                         T = '' }
    sshd           = @{ D = 'OpenSSH server';              T = 'ssh' }
}
$NeededServices = 'wuauserv', 'EventLog', 'mpssvc', 'WinDefend'

function Invoke-Services {
    Section 'Services'
    Info 'Answer N for anything the README lists as a required/critical service.'
    foreach ($name in $RiskyServices.Keys) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if (-not $svc -or $svc.StartType -eq 'Disabled') { continue }
        $entry = $RiskyServices[$name]
        if ($entry.T -and (Test-Required $entry.T)) {
            Good "Keeping $($entry.D) ($name) - the README requires '$($entry.T)'"
            continue
        }
        Warn "$($entry.D) ($name): $($svc.Status), startup $($svc.StartType)"
        if (Confirm-Change "  Stop and disable $name?" -Risky) {
            Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
            Set-Service -Name $name -StartupType Disabled
            Good "Disabled $name"
        }
    }
    foreach ($name in $NeededServices) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if (-not $svc) { continue }
        if ($svc.Status -eq 'Running' -and $svc.StartType -ne 'Disabled') { Good "$name is running"; continue }
        Warn "$name is $($svc.Status), startup $($svc.StartType)"
        if (Confirm-Change "  Enable and start $name?") {
            try {
                Set-Service -Name $name -StartupType Automatic -ErrorAction Stop
                Start-Service -Name $name -ErrorAction Stop
                Good "Started $name"
            } catch { Bad "$name : $($_.Exception.Message)" }
        }
    }
}

# --------------------------------------------------------------- features ---

function Invoke-Features {
    Section 'Windows features'
    foreach ($name in 'SMB1Protocol', 'TelnetClient', 'TelnetServer', 'TFTP', 'SimpleTCP') {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName $name -ErrorAction SilentlyContinue
        if (-not $feature -or $feature.State -ne 'Enabled') { continue }
        Warn "Feature enabled: $name"
        if (Confirm-Change "  Disable feature $name?" -Risky) {
            Disable-WindowsOptionalFeature -Online -FeatureName $name -NoRestart | Out-Null
            Good "Disabled $name (reboot may be needed)"
        }
    }
    Good 'Feature check done'
}

# --------------------------------------------------------------- defender ---

function Invoke-Defender {
    Section 'Microsoft Defender'
    if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) {
        Warn 'Defender cmdlets not available on this image'
        return
    }
    try {
        $status = Get-MpComputerStatus -ErrorAction Stop
        Info "Real-time protection: $($status.RealTimeProtectionEnabled)   Antivirus enabled: $($status.AntivirusEnabled)"
    } catch { Warn 'Could not query Defender status' }

    if (Confirm-Change 'Turn on real-time, behavior, download and script scanning?') {
        Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name 'DisableAntiSpyware' -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -Name 'DisableRealtimeMonitoring' -ErrorAction SilentlyContinue
        try {
            Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false `
                -DisableIOAVProtection $false -DisableScriptScanning $false -ErrorAction Stop
            Good 'Defender protections enabled'
        } catch { Bad "Defender: $($_.Exception.Message) (Tamper Protection may need to be changed in the Security app)" }
    }
    $exclusions = @((Get-MpPreference).ExclusionPath) + @((Get-MpPreference).ExclusionExtension) | Where-Object { $_ }
    if ($exclusions) { Warn "Defender exclusions exist - review them: $($exclusions -join ', ')" }
}

# ----------------------------------------------------------------- report ---

$BadSoftware = 'wireshark|nmap|zenmap|npcap|cain|john the|ophcrack|hashcat|netcat|ncat|angry ip|hydra|metasploit|' +
               'nessus|keylog|teamviewer|anydesk|tightvnc|realvnc|ultravnc|utorrent|bittorrent|qbittorrent|limewire|' +
               'frostwire|ccleaner|aircrack|burp|l0pht|brutus|nikto|sqlmap|steam|minecraft|game|itunes|spotify|tor browser'

function Invoke-Report {
    Section 'Read-only report (nothing is changed or deleted)'
    Set-Content -Path $ReportFile -Value "CyberPatriot report $Stamp on $env:COMPUTERNAME"

    $users = Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue
    $media = 'mp3','mp4','avi','mkv','mov','wav','flac','wmv','m4a','m4v','ogg','aac','mpg','mpeg'
    $tools = 'exe','msi','bat','cmd','ps1','vbs','zip','rar','7z','iso','torrent'
    $mediaHits = @(); $toolHits = @()
    foreach ($dir in $users) {
        Get-ChildItem $dir.FullName -Recurse -Force -File -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notmatch '\\AppData\\' } |
            ForEach-Object {
                $ext = $_.Extension.TrimStart('.').ToLower()
                if ($media -contains $ext) { $mediaHits += $_.FullName }
                elseif ($tools -contains $ext) { $toolHits += $_.FullName }
            }
    }
    Add-Report 'Media files under C:\Users' $mediaHits
    Add-Report 'Executables / scripts / archives under C:\Users' $toolHits

    $uninstallKeys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                     'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    $programs = Get-ItemProperty $uninstallKeys -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName } | Select-Object -ExpandProperty DisplayName | Sort-Object -Unique
    # Flag anything the pasted README mentions, so required software is not removed by mistake.
    $readmePath = Join-Path $ScriptDir 'readme.txt'
    $readme = ''
    if (Test-Path $readmePath) { $readme = [string](Get-Content $readmePath -Raw) }
    $suspicious = @($programs | Where-Object { $_ -match $BadSoftware } | ForEach-Object {
        $null = $_ -match $BadSoftware
        if ($readme -and $readme -match [regex]::Escape($Matches[0])) { "$_   <-- '$($Matches[0])' IS MENTIONED IN THE README, read it before removing" }
        else { $_ }
    })
    Add-Report 'Suspicious installed programs (check README before uninstalling)' $suspicious
    Add-Content -Path $ReportFile -Value "", "##### All installed programs"
    Add-Content -Path $ReportFile -Value $programs

    $shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '\$$' } |
        ForEach-Object { "$($_.Name) -> $($_.Path)" }
    Add-Report 'Non-default file shares' $shares

    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } |
        ForEach-Object { "$($_.TaskPath)$($_.TaskName) -> $(($_.Actions | ForEach-Object { $_.Execute }) -join '; ')" }
    Add-Report 'Non-Microsoft scheduled tasks' $tasks

    $startup = Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue |
        ForEach-Object { "$($_.Name) [$($_.Location)] -> $($_.Command)" }
    Add-Report 'Startup programs' $startup

    $ports = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Sort-Object LocalPort -Unique |
        ForEach-Object {
            $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            "TCP $($_.LocalPort) -> $($proc.ProcessName) (pid $($_.OwningProcess))"
        }
    Add-Report 'Listening TCP ports' $ports

    $hosts = Get-Content "$env:windir\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue |
        Where-Object { $_.Trim() -and -not $_.Trim().StartsWith('#') }
    Add-Report 'Hosts file entries' $hosts

    Info ''
    Info "Full report: $ReportFile"
}

# ------------------------------------------------------------------- menu ---

$Sections = [ordered]@{
    '1' = @{ Name = 'Users and groups';             Run = { Invoke-Users } }
    '2' = @{ Name = 'Password and lockout policy';  Run = { Invoke-PasswordPolicy } }
    '3' = @{ Name = 'Audit policy';                 Run = { Invoke-AuditPolicy } }
    '4' = @{ Name = 'Firewall';                     Run = { Invoke-Firewall } }
    '5' = @{ Name = 'Security options';             Run = { Invoke-SecurityOptions } }
    '6' = @{ Name = 'Services';                     Run = { Invoke-Services } }
    '7' = @{ Name = 'Windows features';             Run = { Invoke-Features } }
    '8' = @{ Name = 'Defender';                     Run = { Invoke-Defender } }
    '9' = @{ Name = 'Report (media, software, shares, tasks, ports)'; Run = { Invoke-Report } }
}

function Show-Reminders {
    Section 'Still on you (the script cannot do these)'
    Info '- Forensics questions (do them BEFORE removing anything)'
    Info '- Uninstall the suspicious programs and delete the media files from the report'
    Info '- Run Windows Update; update the browser and any README-required software'
    Info '- Browser settings: pop-up blocker, safe browsing, no saved passwords'
    Info '- Review shares, scheduled tasks, startup items and odd listening ports in the report'
    Info '- User Rights Assignment and anything else specific to the README (secpol.msc)'
}

. (Join-Path $ScriptDir 'forensics.ps1')

if ($Library) { return }

Start-Transcript -Path (Join-Path $LogDir "harden-windows-$Stamp.log") | Out-Null
Write-Host 'CyberPatriot Windows hardening' -ForegroundColor Cyan
if ($AuditOnly) { Warn 'AUDIT ONLY - nothing will be changed' }
Warn 'Finish the forensics questions before changing users, services or software.'

try {
    if ($All) {
        foreach ($key in $Sections.Keys) { & $Sections[$key].Run }
    } else {
        while ($true) {
            Write-Host ''
            foreach ($key in $Sections.Keys) { Write-Host "  $key) $($Sections[$key].Name)" }
            Write-Host '  F) Forensics questions helper (do these first)'
            Write-Host '  R) Read the README (paste it, fills in users/admins/services)'
            Write-Host '  A) Run everything in order'
            Write-Host '  Q) Quit'
            $choice = (Read-Host 'Choose').Trim().ToUpper()
            if ($choice -eq 'Q') { break }
            if ($choice -eq 'R') { Import-ReadmeConsole; continue }
            if ($choice -eq 'F') { Invoke-ForensicsConsole; continue }
            if ($choice -eq 'A') { foreach ($key in $Sections.Keys) { & $Sections[$key].Run }; continue }
            if ($Sections.Contains($choice)) { & $Sections[$choice].Run } else { Warn 'Not an option' }
        }
    }
    Show-Reminders
} finally {
    Stop-Transcript | Out-Null
}
