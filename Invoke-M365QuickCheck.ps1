<#
.SYNOPSIS
    Free, read-only Microsoft 365 security quick check for small businesses.

.DESCRIPTION
    Eight fast checks against the settings attackers abuse most often in
    small-business Microsoft 365 tenants. It writes an HTML report with
    PASS / WARN / FAIL results and what to do about each one.

    It changes NOTHING. It asks for read-only Microsoft Graph permissions and
    only reads settings.

    Checks: MFA enforcement (Security Defaults / Conditional Access),
    legacy authentication, Global Admin count, user consent to apps, app
    registration by users, guest invitations, password expiration, and
    "Anyone" sharing links in SharePoint/OneDrive.

    The full version (about two dozen checks, including MFA registration,
    admin hygiene, risky third-party apps, inbox rules, mailbox forwarding,
    audit logging, DKIM and SMTP AUTH, plus an incident-response evidence
    script) comes with the book:
    https://radio1one.gumroad.com/l/qvoxbr

.PARAMETER OutputPath
    Where to write the HTML report. Defaults to the current folder.

.EXAMPLE
    .\Invoke-M365QuickCheck.ps1

.NOTES
    Author:  thecyberape
    License: MIT
    Requires: Microsoft.Graph.Authentication module
      Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
    Sign in as a Global Reader (recommended) or Global Administrator.
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Get-Location).Path
)

$ErrorActionPreference = 'Stop'
$FullVersionUrl = 'https://radio1one.gumroad.com/l/qvoxbr'
$results = New-Object System.Collections.ArrayList

function Add-Result {
    param(
        [string]$Area, [string]$Check,
        [ValidateSet('PASS','WARN','FAIL','INFO')][string]$Status,
        [string]$Detail, [string]$Fix = ''
    )
    [void]$results.Add([pscustomobject]@{
        Area = $Area; Check = $Check; Status = $Status; Detail = $Detail; Fix = $Fix
    })
    $color = @{ PASS='Green'; WARN='Yellow'; FAIL='Red'; INFO='Cyan' }[$Status]
    Write-Host ("[{0}] {1} - {2}" -f $Status, $Check, $Detail) -ForegroundColor $color
}

function Get-GraphAll {
    param([string]$Uri)
    $items = @()
    $next = $Uri
    while ($next) {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject
        if ($resp.value) { $items += $resp.value }
        $next = $resp.'@odata.nextLink'
    }
    return ,$items
}

# ---------------------------------------------------------------- connect
if (-not (Get-Module -ListAvailable Microsoft.Graph.Authentication)) {
    throw "Microsoft.Graph.Authentication is not installed. Run: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser"
}
Import-Module Microsoft.Graph.Authentication
Write-Host "Connecting to Microsoft Graph (read-only scopes)..." -ForegroundColor Cyan
Connect-MgGraph -NoWelcome -Scopes @(
    'Policy.Read.All', 'Directory.Read.All', 'RoleManagement.Read.Directory',
    'Organization.Read.All', 'SharePointTenantSettings.Read.All'
)

$org = (Invoke-MgGraphRequest -Method GET -Uri 'v1.0/organization' -OutputType PSObject).value | Select-Object -First 1
$tenantName = $org.displayName

# 1-2. MFA baseline and legacy authentication
$caPolicies = @()
try { $caPolicies = Get-GraphAll 'v1.0/identity/conditionalAccess/policies' } catch { }
$enabledCa = @($caPolicies | Where-Object { $_.state -eq 'enabled' })
$secDefaults = Invoke-MgGraphRequest -Method GET -Uri 'v1.0/policies/identitySecurityDefaultsEnforcementPolicy' -OutputType PSObject

if ($secDefaults.isEnabled) {
    Add-Result 'Identity' 'MFA enforced' 'PASS' 'Security Defaults are ON (MFA for everyone).'
    Add-Result 'Identity' 'Legacy authentication blocked' 'PASS' 'Security Defaults block legacy authentication.'
} else {
    $mfaAll = $enabledCa | Where-Object {
        ($_.conditions.users.includeUsers -contains 'All') -and
        ($_.grantControls.builtInControls -contains 'mfa' -or $_.grantControls.authenticationStrength)
    }
    if ($mfaAll) {
        Add-Result 'Identity' 'MFA enforced' 'PASS' "Conditional Access requires MFA for all users: $(($mfaAll | Select-Object -ExpandProperty displayName) -join '; ')"
    } else {
        Add-Result 'Identity' 'MFA enforced' 'FAIL' 'Security Defaults are off and no enabled Conditional Access policy requires MFA for all users.' 'Turn on Security Defaults today, or create a CA policy: All users, All cloud apps, require MFA (exclude a break-glass account).'
    }
    $legacy = $enabledCa | Where-Object {
        ($_.conditions.clientAppTypes -contains 'exchangeActiveSync' -or $_.conditions.clientAppTypes -contains 'other') -and
        ($_.grantControls.builtInControls -contains 'block')
    }
    if ($legacy) {
        Add-Result 'Identity' 'Legacy authentication blocked' 'PASS' "Blocked by: $(($legacy | Select-Object -ExpandProperty displayName) -join '; ')"
    } else {
        Add-Result 'Identity' 'Legacy authentication blocked' 'FAIL' 'Nothing blocks legacy authentication, which skips MFA entirely.' 'Find what still uses it (old scanners, mail clients), then add a CA policy blocking Exchange ActiveSync + Other clients.'
    }
}

# 3. Global admin count
$gaRole = (Invoke-MgGraphRequest -Method GET -Uri "v1.0/directoryRoles?`$filter=roleTemplateId eq '62e90394-69f5-4237-9190-012177145e10'" -OutputType PSObject).value | Select-Object -First 1
$gaMembers = @()
if ($gaRole) { $gaMembers = Get-GraphAll "v1.0/directoryRoles/$($gaRole.id)/members" }
$gaCount = $gaMembers.Count
if ($gaCount -lt 2) {
    Add-Result 'Admin' 'Global Administrator count' 'WARN' "$gaCount Global Admin(s)." 'Keep 2-4, including one break-glass account so you cannot lock yourself out.'
} elseif ($gaCount -gt 4) {
    Add-Result 'Admin' 'Global Administrator count' 'FAIL' "$gaCount Global Admins." 'Reduce to 2-4. Move day-to-day admins to narrower roles.'
} else {
    Add-Result 'Admin' 'Global Administrator count' 'PASS' "$gaCount Global Admins."
}

# 4-6. Authorization policy
$auth = Invoke-MgGraphRequest -Method GET -Uri 'v1.0/policies/authorizationPolicy' -OutputType PSObject
$grant = @($auth.defaultUserRolePermissions.permissionGrantPoliciesAssigned)
if ($grant | Where-Object { $_ -match 'microsoft-user-default-legacy' }) {
    Add-Result 'Apps' 'User consent to apps' 'FAIL' 'Any user can let any app read company data. This is how consent phishing works.' 'Entra > Enterprise apps > Consent and permissions: verified publishers only, or no user consent.'
} else {
    Add-Result 'Apps' 'User consent to apps' 'PASS' 'User consent is restricted.'
}
if ($auth.defaultUserRolePermissions.allowedToCreateApps) {
    Add-Result 'Apps' 'Users can register apps' 'WARN' 'Any user can register applications.' 'Entra > User settings: "Users can register applications" = No.'
} else {
    Add-Result 'Apps' 'Users can register apps' 'PASS' 'App registration restricted to admins.'
}
if ($auth.allowInvitesFrom -eq 'everyone') {
    Add-Result 'Guests' 'Who can invite guests' 'WARN' 'Anyone, including guests, can invite more guests.' 'External collaboration settings: limit invites to members or admins.'
} else {
    Add-Result 'Guests' 'Who can invite guests' 'PASS' "Guest invites limited to: $($auth.allowInvitesFrom)"
}

# 7. Password expiration
$domains = (Invoke-MgGraphRequest -Method GET -Uri 'v1.0/domains' -OutputType PSObject).value | Where-Object { $_.isVerified }
$expiring = @($domains | Where-Object { $_.passwordValidityPeriodInDays -and $_.passwordValidityPeriodInDays -lt 2147483647 })
if ($expiring.Count -gt 0) {
    Add-Result 'Identity' 'Password expiration' 'WARN' "Passwords expire on: $(($expiring | ForEach-Object { "$($_.id) ($($_.passwordValidityPeriodInDays) days)" }) -join ', ')" 'With MFA enforced, set passwords to never expire (current Microsoft/NIST guidance).'
} else {
    Add-Result 'Identity' 'Password expiration' 'PASS' 'Passwords never expire (correct when MFA is enforced).'
}

# 8. SharePoint / OneDrive "Anyone" links
try {
    $spo = Invoke-MgGraphRequest -Method GET -Uri 'v1.0/admin/sharepoint/settings' -OutputType PSObject
    if ($spo.sharingCapability -eq 'externalUserAndGuestSharing') {
        Add-Result 'Data' '"Anyone" sharing links' 'WARN' 'Tenant allows "Anyone" links that need no sign-in.' 'SharePoint admin > Policies > Sharing: "New and existing guests", or at least set expiry and View-only defaults.'
    } else {
        Add-Result 'Data' '"Anyone" sharing links' 'PASS' "Sharing level: $($spo.sharingCapability)"
    }
} catch {
    Add-Result 'Data' '"Anyone" sharing links' 'INFO' 'Could not read SharePoint sharing settings.'
}

Disconnect-MgGraph | Out-Null

# ---------------------------------------------------------------- report
function ConvertTo-SafeHtml([string]$s) { [System.Net.WebUtility]::HtmlEncode("$s") }
$counts = @{}
foreach ($s in 'FAIL','WARN','PASS','INFO') { $counts[$s] = @($results | Where-Object Status -eq $s).Count }
$order = @{ FAIL = 0; WARN = 1; PASS = 2; INFO = 3 }
$rows = foreach ($r in ($results | Sort-Object @{ e = { $order[$_.Status] } }, Area)) {
    "<tr class='$($r.Status.ToLower())'><td><span class='tag'>$($r.Status)</span></td><td>$(ConvertTo-SafeHtml $r.Area)</td><td><b>$(ConvertTo-SafeHtml $r.Check)</b><div class='d'>$(ConvertTo-SafeHtml $r.Detail)</div></td><td>$(ConvertTo-SafeHtml $r.Fix)</td></tr>"
}
$notChecked = @(
    'Users and admins without MFA registered, and SMS-only MFA',
    'Admins using their admin account for everyday email',
    'Third-party apps holding mail or file access, and who approved them',
    'Inbox rules that forward, delete, or hide mail (a classic sign of a hijacked mailbox)',
    'Mailboxes forwarding to outside addresses, and external auto-forwarding',
    'Unified audit log and mailbox auditing',
    'DKIM signing and tenant-wide SMTP AUTH',
    'Licensed accounts nobody has signed in to for 90+ days',
    'Old guest accounts',
    'Conditional Access policies stuck in report-only'
) | ForEach-Object { "<li>$_</li>" }

$stamp = Get-Date -Format 'yyyy-MM-dd HH:mm'
$html = @"
<!doctype html><html><head><meta charset='utf-8'><title>M365 Quick Check - $(ConvertTo-SafeHtml $tenantName)</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:32px;color:#12181F;background:#fff;max-width:1100px}
h1{margin:0 0 4px}.sub{color:#5a6577;margin-bottom:20px}
.cards{display:flex;gap:12px;margin:16px 0 24px}.card{padding:12px 18px;border-radius:8px;min-width:90px}
.card b{display:block;font-size:26px}.c-fail{background:#fde8e8}.c-warn{background:#fff4d6}.c-pass{background:#e4f6ea}
table{border-collapse:collapse;width:100%}th,td{text-align:left;vertical-align:top;padding:10px;border-bottom:1px solid #e3e7ee;font-size:14px}
th{background:#12181F;color:#fff}.d{color:#5a6577;margin-top:4px}
.tag{font-weight:700;font-size:12px;padding:3px 8px;border-radius:4px}
.fail .tag{background:#c62828;color:#fff}.warn .tag{background:#E8A33D;color:#12181F}.pass .tag{background:#2e7d32;color:#fff}.info .tag{background:#1565c0;color:#fff}
.more{margin-top:28px;padding:18px 22px;border:2px solid #E8A33D;border-radius:10px;background:#fbf6ec}
.more h2{margin:0 0 8px;font-size:18px}.more li{margin:4px 0}.more a{color:#B97323;font-weight:700}
footer{margin-top:24px;color:#8a93a3;font-size:12px}
</style></head><body>
<h1>Microsoft 365 Quick Check</h1>
<div class='sub'>$(ConvertTo-SafeHtml $tenantName) &middot; $stamp &middot; free version, 8 read-only checks</div>
<div class='cards'>
<div class='card c-fail'><b>$($counts.FAIL)</b>Fail</div>
<div class='card c-warn'><b>$($counts.WARN)</b>Warn</div>
<div class='card c-pass'><b>$($counts.PASS)</b>Pass</div>
</div>
<table><tr><th>Result</th><th>Area</th><th>Check</th><th>What to do</th></tr>
$($rows -join "`n")
</table>
<div class='more'>
<h2>Not checked by the free version</h2>
<ul>$($notChecked -join '')</ul>
<p>The full Quick Audit checks all of these. It comes with an incident-response evidence script, an Excel security workbook, and the book <i>Microsoft 365 Security: A Practical Small-Business Hardening Guide</i>. <a href='$FullVersionUrl'>Get the full toolkit</a></p>
</div>
<footer>Invoke-M365QuickCheck.ps1 by thecyberape &middot; MIT license &middot; read-only, no settings were changed.</footer>
</body></html>
"@

$file = Join-Path $OutputPath ("M365-QuickCheck-{0}.html" -f (Get-Date -Format 'yyyyMMdd-HHmm'))
$html | Out-File -FilePath $file -Encoding utf8
Write-Host ""
Write-Host "Report written to $file" -ForegroundColor Green
Write-Host ("FAIL: {0}  WARN: {1}  PASS: {2}" -f $counts.FAIL, $counts.WARN, $counts.PASS)
Write-Host "Want the other checks (MFA registration, inbox rules, forwarding, risky apps, audit log)? $FullVersionUrl" -ForegroundColor Yellow
