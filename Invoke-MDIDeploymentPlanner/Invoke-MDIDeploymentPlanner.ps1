# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#Requires -Version 7.2

<#
.SYNOPSIS
    Interactive MDI Deployment Planning tool — generates a tailored deployment
    plan (JSON + HTML + PDF) for Microsoft Defender for Identity.

.DESCRIPTION
    Guides security professionals through a structured questionnaire covering the
    customer's AD topology, DC inventory, connectivity, MDE deployment state, and
    feature requirements. No Active Directory connection or external service access
    is required — all input is gathered interactively.

    Based on the answers, the tool:
      - Recommends the correct MDI sensor version (v2.x or v3.x) per server group
      - Estimates sensor CPU/RAM requirements using the official MDI sizing table
      - Calculates the required number of Directory Service Accounts (DSA)
      - Recommends the appropriate Windows event auditing approach
      - Generates a phased, actionable deployment checklist
      - Flags blockers and warnings (missing license, SSL inspection, legacy OS, etc.)
      - Pre-populates all Set-MDIConfiguration cmdlets with -WhatIf and safety banners

    Outputs:
      - MDIDeploymentPlan-<CustomerName>-<timestamp>.json  — raw answers + derived recommendations
      - MDIDeploymentPlan-<CustomerName>-<timestamp>.html  — self-contained HTML report with
        summary cards, server table, DSA config, connectivity guide, and checklist
      - MDIDeploymentPlan-<CustomerName>-<timestamp>.pdf   — optional; generated via Microsoft Edge

.PARAMETER OutputPath
    Directory in which to save the JSON and HTML output files.
    Default: Report\ subfolder within the script's directory (created automatically if it does not exist).

.PARAMETER CustomerName
    Optional customer name shown in the report title and header.
    If omitted, the script prompts for it interactively.

.PARAMETER OpenInBrowser
    Opens the generated HTML report in the default browser after creation.

.PARAMETER Plan
    Path to a previously exported MDIDeploymentPlan JSON file. When supplied, the
    interactive questionnaire is skipped entirely and the report is rebuilt directly
    from the saved answers. Useful for re-generating a report after editing the JSON,
    for automation, or for running the QA harness non-interactively.

.PARAMETER NoPdf
    Suppresses the "Generate PDF?" and "Open in browser?" prompts after report
    generation. Useful when running non-interactively via -Plan.

.EXAMPLE
    .\Invoke-MDIDeploymentPlanner.ps1

.EXAMPLE
    .\Invoke-MDIDeploymentPlanner.ps1 -CustomerName 'Zava' -OpenInBrowser

.EXAMPLE
    .\Invoke-MDIDeploymentPlanner.ps1 -CustomerName 'Zava' -OutputPath 'C:\Reports' -OpenInBrowser

.EXAMPLE
    # Re-generate an existing plan non-interactively (no prompts)
    .\Invoke-MDIDeploymentPlanner.ps1 -Plan '.\Report\MDIDeploymentPlan-Zava-20260526-120000.json' -OutputPath '.\Report' -NoPdf

.NOTES
    Author       : Matthias Scharl — Security Cloud Solution Architect at Microsoft
    Contributors : Konstantin Klein — Security Cloud Solution Architect at Microsoft
                   Robert Stampfer  — Security Cloud Solution Architect at Microsoft

    Copyright (c) Microsoft Corporation.  All rights reserved.
    Use of this sample source code is subject to the terms of the Microsoft
    license agreement under which you licensed this sample source code. If
    you did not accept the terms of the license agreement, you are not
    authorized to use this sample source code.
    THE SAMPLE SOURCE CODE IS PROVIDED "AS IS", WITH NO WARRANTIES.

    Minimum required Entra ID role to create the MDI workspace: Security Administrator
    No Azure or Microsoft Graph permissions are required to run this script.

    Reference documentation:
      Deployment overview  : https://learn.microsoft.com/en-us/defender-for-identity/deploy/deploy-defender-identity
      Prerequisites v2     : https://learn.microsoft.com/en-us/defender-for-identity/deploy/prerequisites-sensor-version-2
      Prerequisites v3     : https://learn.microsoft.com/en-us/defender-for-identity/deploy/prerequisites-sensor-version-3
      Capacity planning    : https://learn.microsoft.com/en-us/defender-for-identity/deploy/capacity-planning
      Sizing tool          : https://aka.ms/mdi/sizingtool
      DSA / gMSA           : https://learn.microsoft.com/en-us/defender-for-identity/deploy/create-directory-service-account-gmsa
      Windows event audit  : https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-windows-event-collection
      Proxy configuration  : https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-proxy
      Install sensor v2    : https://learn.microsoft.com/en-us/defender-for-identity/deploy/install-sensor
      Activate sensor v3   : https://learn.microsoft.com/en-us/defender-for-identity/deploy/activate-sensor
      AD FS / AD CS / EC   : https://learn.microsoft.com/en-us/defender-for-identity/deploy/active-directory-federation-services
      Multi-forest         : https://learn.microsoft.com/en-us/defender-for-identity/deploy/multi-forest
      Test-MdiReadiness    : https://github.com/microsoft/Microsoft-Defender-for-Identity/tree/main/Test-MdiReadiness
      PS module            : https://www.powershellgallery.com/packages/DefenderForIdentity/
#>

[CmdletBinding()]
param (
    [Parameter()]
    [string] $OutputPath,

    [Parameter()]
    [string] $CustomerName,

    [Parameter()]
    [switch] $OpenInBrowser,

    [Parameter()]
    [string] $Plan,  # Path to an existing plan JSON — skips the questionnaire (used by QA runner)

    [Parameter()]
    [switch] $NoPdf  # Skip PDF generation prompt (used by QA runner / CI)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

<#
===============================================================================
  TABLE OF CONTENTS
===============================================================================
  Use Ctrl+G (VS Code) to jump to a line number directly.

  ── Lookup Tables (L125) ─────────────────────────────────────────────────────
    L127  $script:SizingTable     CPU/RAM lookup by traffic bucket
    L138  $script:OSVersions      Ordered list of supported OS choices
    L146  $script:TrafficBuckets  Ordered list of traffic range choices
    L157  $script:TrustTypes      Forest trust type choices

  ── Helper Functions (L166) ──────────────────────────────────────────────────
    L171  Read-KeyChar            Low-level single-keypress reader (RawUI + fallback)
    L189  Write-Section           Clears screen, prints answers-so-far box + progress bar + section title
    L292  Write-SubSection        Prints a sub-heading within a section
    L299  Write-DCGroupTable      Prints live DC group summary table with v2/v3 preview
    L340  Read-Choice             Single-keypress option picker (≤9) or Read-Host fallback (>9)
    L376  Read-YesNo              Single-keypress Y/N prompt with default
    L389  Read-Int                Validated integer prompt with min/max/default
    L404  Read-NonEmptyText       Prompt that rejects blank input
    L412  ConvertTo-HtmlEncoded   HTML-encodes a string for safe report output
    L417  Get-SafeName            Sanitises a string for use as a filename

  ── Questionnaire (L424) ─────────────────────────────────────────────────────
    L429  Invoke-Section1         Licensing — license status & type
    L464  Invoke-Section2         ATA Migration — ATA presence & decommission state
    L485  Invoke-Section3         Forest & Domain Topology — forest/domain count, trust types
    L512  Invoke-Section4         DC Inventory — OS groups, roles, RODC, traffic, count (with Y/N/E loop)
    L568  Invoke-Section5         Standalone Servers — AD FS / AD CS / Entra Connect
    L614  Invoke-Section6         Connectivity — internet method, proxy, SSL inspection
    L652  Invoke-Section7         MDE — sensor v3.x eligibility per DC
    L682  Invoke-Section8         Feature Requirements — VPN integration, syslog
    L694  Invoke-Section9         DSA — gMSA vs regular account, KDS Root Key, per-forest
    L800  Invoke-Section10        Identity & PAM Integrations — Okta, CyberArk Identity, SailPoint, PAM services
    L840  Show-ReviewScreen       Full-screen review of all 10 answers; returns G or 1-9 or 0 (§10)
    L882  Invoke-Questionnaire    Main wrapper — runs sections 1-10, review loop, returns $answers

  ── Logic Engine (L811) ──────────────────────────────────────────────────────
    L813  Get-SensorRecommendation  Returns 'v2.x' or 'v3.x' for a DC group
    L831  Get-SizingEstimate        Looks up CPU/RAM sizing from traffic bucket
    L836  Get-DSARequirements       Calculates required DSA count & notes from topology
    L855  Get-AuditingApproach      Returns auditing method object (Automatic vs PowerShell)
    L879  Build-ServerGroups        Builds flat server-group list from $answers (DCs + standalones)
    L957  Get-Warnings              Returns list of BLOCKER / WARNING / INFO items
    L1058 Build-DeploymentChecklist Builds ordered phase-by-phase checklist hashtable list

  ── Output (L1251) ───────────────────────────────────────────────────────────
    L1253 Export-PlanJson           Serialises full plan to timestamped JSON file
    L1283 New-HtmlReport            Generates Fluent UI HTML deployment plan report
    L1810 Export-PlanPdf            Exports HTML to PDF via Microsoft Edge CDP (no header/footer)

  ── Main (L1931) ─────────────────────────────────────────────────────────────
    L1931 #region Main              Resolves OutputPath, shows banner, runs questionnaire,
                                    builds derived data, writes JSON + HTML, optional PDF
===============================================================================
#>

#region ─── Lookup Tables ────────────────────────────────────────────────────

$script:SizingTable = @{
    '0-1k'     = @{ CPU = 0.25; RAM = 2.5  }
    '1k-5k'    = @{ CPU = 0.75; RAM = 6.0  }
    '5k-10k'   = @{ CPU = 1.00; RAM = 6.5  }
    '10k-20k'  = @{ CPU = 2.00; RAM = 9.0  }
    '20k-50k'  = @{ CPU = 3.50; RAM = 9.5  }
    '50k-75k'  = @{ CPU = 5.50; RAM = 11.5 }
    '75k-100k' = @{ CPU = 7.50; RAM = 13.5 }
    'Unknown'  = $null
}

$script:OSVersions = @(
    'Windows Server 2016'
    'Windows Server 2019'
    'Windows Server 2022'
    'Windows Server 2025'
    'Other / Legacy'
)

$script:TrafficBuckets = @(
    '0-1k'
    '1k-5k'
    '5k-10k'
    '10k-20k'
    '20k-50k'
    '50k-75k'
    '75k-100k'
    'Unknown'
)

$script:TrustTypes = @(
    'Two-way Kerberos (full trust)'
    'One-way trust'
    'Non-Kerberos trust'
    'No trust'
)

#endregion

#region ─── Helper Functions ─────────────────────────────────────────────────

# ── Single-keypress low-level reader ─────────────────────────────────────────
# Returns the character pressed. Falls back silently to Read-Host in
# non-interactive hosts (VS Code, ISE, remoting) where RawUI is unavailable.
function Read-KeyChar {
    param ([string[]] $ValidChars)
    $interactive = $Host.Name -eq 'ConsoleHost' -and $Host.UI.RawUI.WindowSize.Width -gt 0
    if (-not $interactive) {
        # Fallback: read a line and return its first char (or empty → Enter)
        $line = (Read-Host).Trim()
        return $(if ($line.Length -gt 0) { $line[0].ToString().ToUpper() } else { '' })
    }
    while ($true) {
        $key = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
        # Enter key (VirtualKeyCode 13) → treat as default
        if ($key.VirtualKeyCode -eq 13) { return '' }
        $ch = $key.Character.ToString().ToUpper()
        if (-not $ValidChars -or $ch -in $ValidChars) { return $ch }
    }
}

# ── Section header with progress bar + answers summary ───────────────────────
function Write-Section {
    param (
        [string]    $Title,
        [int]       $SectionNum,
        [int]       $TotalSections = 10,
        [hashtable] $Answers = $null
    )

    Clear-Host

    # ── Compact answers-so-far summary ───────────────────────────────────────
    if ($Answers -and $SectionNum -gt 1) {
        Write-Host '  ┌─ Answers so far ──────────────────────────────────────────────────┐' -ForegroundColor DarkGray

        # Section 1 — Licensing (bracket notation: safe under Set-StrictMode)
        if ($Answers.Licensing['Status']) {
            $lic = $Answers.Licensing['Status'] -replace '^Yes — license confirmed$', 'Confirmed'
            $lic = $lic -replace '^No — license not yet procured$', 'Not procured'
            $lic = $lic -replace '^Unknown — needs verification$', 'Unknown'
            $licType = if ($Answers.Licensing['Type'] -and $Answers.Licensing['Type'] -ne 'N/A') { " ($($Answers.Licensing['Type']))" } else { '' }
            Write-Host "  │  1. License      : $lic$licType" -ForegroundColor DarkGray
        }

        # Section 2 — ATA
        if ($Answers.ATA -and $Answers.ATA.Count -gt 0) {
            $ataLine = if ($Answers.ATA['IsDeployed']) {
                if ($Answers.ATA['StillActive']) { 'Present — ACTIVE (blocker)' } else { 'Present — decommissioned' }
            } else { 'Not deployed' }
            Write-Host "  │  2. ATA          : $ataLine" -ForegroundColor DarkGray
        }

        # Section 3 — Topology
        if ($Answers.Topology['ForestCount']) {
            Write-Host "  │  3. Topology     : $($Answers.Topology['ForestCount']) forest(s), $($Answers.Topology['DomainCount']) domain(s)" -ForegroundColor DarkGray
        }

        # Section 4 — DC Groups
        if ($Answers.DCGroups -and $Answers.DCGroups.Count -gt 0) {
            $totalDCs = 0; foreach ($g in $Answers.DCGroups) { $totalDCs += [int]$g['Count'] }
            Write-Host "  │  4. DC Inventory : $($Answers.DCGroups.Count) group(s), $totalDCs DC(s) total" -ForegroundColor DarkGray
        }

        # Section 5 — Standalone
        if ($Answers.StandaloneServers -and $Answers.StandaloneServers.Count -gt 0) {
            $sTotal = 0
            foreach ($k in @('ADFS','ADCS','EntraConnectActive','EntraConnectStaging')) {
                if ($Answers.StandaloneServers[$k]) { $sTotal += [int]$Answers.StandaloneServers[$k]['Count'] }
            }
            Write-Host "  │  5. Role Servers  : $sTotal server(s)" -ForegroundColor DarkGray
        }

        # Section 6 — Connectivity
        if ($Answers.Connectivity['Method']) {
            $method = $Answers.Connectivity['Method'] -replace '^Direct access.*$', 'Direct'
            $method = $method -replace '^Forward proxy$', 'Forward proxy'
            $method = $method -replace '^Azure ExpressRoute.*$', 'ExpressRoute'
            $method = $method -replace '^Firewall.*$', 'Firewall + allowlist'
            $sslWarn = if ($Answers.Connectivity['SSLInspection']) { ' ⚠ SSL inspection!' } else { '' }
            Write-Host "  │  6. Connectivity : $method$sslWarn" -ForegroundColor DarkGray
        }

        # Section 7 — MDE
        if ($Answers.MDE['DeployedOnDCs']) {
            $mdeShort = $Answers.MDE['DeployedOnDCs'] -replace '^Yes — deployed on ALL DCs$', 'All DCs'
            $mdeShort = $mdeShort -replace '^Yes — deployed on SOME DCs \(mixed\)$', 'Mixed'
            $mdeShort = $mdeShort -replace '^No — not deployed$', 'Not deployed'
            Write-Host "  │  7. MDE          : $mdeShort" -ForegroundColor DarkGray
        }

        # Section 8 — Features
        if ($Answers.Features.Count -gt 0) {
            $vpn    = if ($Answers.Features['VPNIntegration'])      { 'VPN' } else { '' }
            $syslog = if ($Answers.Features['SyslogNotifications']) { 'Syslog' } else { '' }
            $feats  = (@($vpn, $syslog) | Where-Object { $_ }) -join ', '
            $featLine = if ($feats) { "Required: $feats (→ v2.x)" } else { 'No v3.x-blocking features' }
            Write-Host "  │  8. Features     : $featLine" -ForegroundColor DarkGray
        }

        # Section 9 — DSA
        if ($Answers.DSA -and $Answers.DSA.Count -gt 0) {
            $dsaShort = $Answers.DSA['Type'] -replace '^Group Managed Service Account \(gMSA\).*$', 'gMSA (recommended)'
            $dsaShort = $dsaShort -replace '^Regular AD user account$', 'Regular AD account'
            Write-Host "  │  9. DSA          : $dsaShort" -ForegroundColor DarkGray
        }

        # Section 10 — Integrations
        if ($Answers.Integrations -and $Answers.Integrations.Count -gt 0) {
            $intParts = [System.Collections.Generic.List[string]]::new()
            if ($Answers.Integrations['Okta'])       { $intParts.Add('Okta') }
            if ($Answers.Integrations['CyberArkId']) { $intParts.Add('CyberArk Identity') }
            if ($Answers.Integrations['SailPoint'])  { $intParts.Add('SailPoint') }
            if ($Answers.Integrations['PamEnabled']) {
                $vendor = $Answers.Integrations['PamVendor'] -replace ' .*$',''
                $intParts.Add("PAM ($vendor)")
            }
            $intStr = if ($intParts.Count -gt 0) { $intParts -join ', ' } else { 'None selected' }
            Write-Host "  │  10. Integrations: $intStr" -ForegroundColor DarkGray
        }

        Write-Host '  └───────────────────────────────────────────────────────────────────┘' -ForegroundColor DarkGray
        Write-Host ''
    }

    # ── Progress bar ─────────────────────────────────────────────────────────
    $filled = [int][Math]::Round(20 * $SectionNum / $TotalSections)
    $empty  = 20 - $filled
    $bar    = ('█' * $filled) + ('░' * $empty)
    Write-Host "  [$bar] $SectionNum / $TotalSections" -ForegroundColor Cyan

    # ── Section title ─────────────────────────────────────────────────────────
    $line = '─' * 70
    Write-Host ''
    Write-Host $line -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan
}

function Write-SubSection {
    param ([string] $Title)
    Write-Host ''
    Write-Host "  ► $Title" -ForegroundColor Yellow
}

# ── DC group live summary table ───────────────────────────────────────────────
function Write-DCGroupTable {
    param ($DCGroups, $Answers)

    if ($DCGroups.Count -eq 0) { return }

    Write-Host ''
    Write-Host '  ┌─ DC Groups entered so far ────────────────────────────────────────┐' -ForegroundColor DarkGray
    Write-Host '  │  #   OS Version            Count   v2/v3 (preview)   Co-hosted   │' -ForegroundColor DarkGray
    Write-Host '  ├───────────────────────────────────────────────────────────────────┤' -ForegroundColor DarkGray

    $i = 1
    foreach ($g in $DCGroups) {
        # Quick sensor version preview (same logic as Get-SensorRecommendation)
        $v3Eligible = $g.OSVersion -in @('Windows Server 2019', 'Windows Server 2022', 'Windows Server 2025')
        $vpnBlock   = $Answers.Features -and $Answers.Features['VPNIntegration']
        $sysBlock   = $Answers.Features -and $Answers.Features['SyslogNotifications']
        $mdeAnswered = $Answers.MDE -and $Answers.MDE['DeployedOnDCs']
        $mdeOK      = $false
        if ($mdeAnswered) {
            $mdeStatus = $Answers.MDE['DeployedOnDCs']
            $mdeOK = switch ($mdeStatus) {
                'Yes — deployed on ALL DCs'           { $true }
                'Yes — deployed on SOME DCs (mixed)'  { $g.OSVersion -in $Answers.MDE['OSVersionsWithMDE'] }
                default { $false }
            }
        }
        # If OS is eligible but MDE not yet answered, show provisional 'v3.x?' instead of a false v2.x
        $preview = if ($v3Eligible -and -not $vpnBlock -and -not $sysBlock) {
            if ($mdeAnswered) { if ($mdeOK) { 'v3.x' } else { 'v2.x' } } else { 'v3.x?' }
        } else { 'v2.x' }
        $previewColor = if ($preview -eq 'v3.x') { 'Green' } elseif ($preview -eq 'v3.x?') { 'Yellow' } else { 'Gray' }

        $osShort    = $g.OSVersion -replace 'Windows Server ', 'WS ' -replace 'Other / Legacy', 'Other/Legacy'
        $roles      = if ($g.CoHostedRoles -and $g.CoHostedRoles.Count -gt 0) { $g.CoHostedRoles -join ',' } else { '—' }
        $rodc       = if ($g.IsRODC) { ' (RODC)' } else { '' }
        $line = "  │  {0,-3} {1,-22} {2,-7} " -f $i, "$osShort$rodc", $g['Count']
        Write-Host $line -ForegroundColor DarkGray -NoNewline
        Write-Host ("{0,-17}" -f $preview) -ForegroundColor $previewColor -NoNewline
        Write-Host "$roles   │" -ForegroundColor DarkGray
        $i++
    }
    Write-Host '  └───────────────────────────────────────────────────────────────────┘' -ForegroundColor DarkGray
}

# ── Single-keypress choice prompt ────────────────────────────────────────────
function Read-Choice {
    param (
        [string]   $Prompt,
        [string[]] $Options,
        [int]      $Default = 1,
        [int]      $Recommended = -1
    )
    Write-Host ''
    Write-Host "  $Prompt" -ForegroundColor White
    for ($i = 0; $i -lt $Options.Count; $i++) {
        $num = $i + 1
        $rec = if ($Recommended -eq $num) { '  ← recommended' } else { '' }
        $col = if ($Recommended -eq $num) { 'Green' } else { 'Gray' }
        Write-Host "    [$num] $($Options[$i])$rec" -ForegroundColor $col
    }

    # Single-keypress for ≤9 options
    if ($Options.Count -le 9) {
        $valid = (1..$Options.Count | ForEach-Object { "$_" })
        Write-Host "  Choice — press a key, or Enter for default [$Default]: " -ForegroundColor White -NoNewline
        $ch = Read-KeyChar -ValidChars $valid
        if ([string]::IsNullOrEmpty($ch)) { $ch = "$Default" }
        Write-Host $ch -ForegroundColor Cyan
        return $Options[[int]$ch - 1]
    }

    # Fallback for >9 options
    do {
        $raw = Read-Host "  Enter choice (1-$($Options.Count)) [Enter = $Default]"
        if ([string]::IsNullOrWhiteSpace($raw)) { $raw = "$Default" }
        $val = 0
    } while (-not ([int]::TryParse($raw, [ref]$val)) -or $val -lt 1 -or $val -gt $Options.Count)
    return $Options[$val - 1]
}

# ── Single-keypress Yes/No prompt ────────────────────────────────────────────
function Read-YesNo {
    param (
        [string] $Prompt,
        [bool]   $Default = $false
    )
    $defStr = if ($Default) { 'Y' } else { 'N' }
    Write-Host "  $Prompt [Y/N — Enter = $defStr]: " -ForegroundColor White -NoNewline
    $ch = Read-KeyChar -ValidChars @('Y', 'N')
    if ([string]::IsNullOrEmpty($ch)) { $ch = $defStr }
    Write-Host $ch -ForegroundColor Cyan
    return $ch -eq 'Y'
}

function Read-Int {
    param (
        [string] $Prompt,
        [int]    $Min     = 1,
        [int]    $Max     = 9999,
        [int]    $Default = 1
    )
    do {
        $raw = Read-Host "  $Prompt [Enter = $Default]"
        if ([string]::IsNullOrWhiteSpace($raw)) { $raw = "$Default" }
        $val = 0
    } while (-not ([int]::TryParse($raw, [ref]$val)) -or $val -lt $Min -or $val -gt $Max)
    return $val
}

function Read-NonEmptyText {
    param ([string] $Prompt)
    do {
        $val = (Read-Host "  $Prompt").Trim()
    } while ([string]::IsNullOrWhiteSpace($val))
    return $val
}

function ConvertTo-HtmlEncoded {
    param ([string] $Text)
    return [System.Net.WebUtility]::HtmlEncode($Text)
}

function Get-SafeName {
    param ([string] $Name)
    return $Name -replace '[^A-Za-z0-9_-]', '_' -replace '_{2,}', '_' -replace '^_|_$', ''
}

# Recursively convert PSCustomObject (from ConvertFrom-Json) back to hashtable
function ConvertTo-NestedHashtable {
    param ($InputObject)
    if ($null -eq $InputObject)                                               { return $null }
    if ($InputObject -is [System.Management.Automation.PSCustomObject]) {
        $ht = @{}
        foreach ($prop in $InputObject.PSObject.Properties) {
            $ht[$prop.Name] = ConvertTo-NestedHashtable $prop.Value
        }
        return $ht
    }
    if ($InputObject -is [System.Collections.IEnumerable] -and
        $InputObject -isnot [string]) {
        return @($InputObject | ForEach-Object { ConvertTo-NestedHashtable $_ })
    }
    return $InputObject
}

# Load a previously exported plan JSON and return the answers hashtable
function Import-PlanAnswers {
    param ([string] $JsonPath)
    $json    = Get-Content -Path $JsonPath -Raw | ConvertFrom-Json
    $answers = ConvertTo-NestedHashtable $json.Answers
    # Rebuild DCGroups as List[hashtable]
    $dcList  = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($g in $answers.DCGroups) {
        if ($g -is [hashtable]) { $dcList.Add($g) }
    }
    $answers.DCGroups = $dcList
    # Normalise sections that may be absent or empty in older plan formats
    if (-not $answers.ContainsKey('Features') -or -not ($answers.Features -is [hashtable]) -or -not $answers.Features.ContainsKey('VPNIntegration')) {
        $answers.Features = @{ VPNIntegration = $false; SyslogNotifications = $false }
    }
    if (-not $answers.ContainsKey('Integrations') -or -not ($answers.Integrations -is [hashtable])) {
        $answers.Integrations = @{ Okta = $false; CyberArkId = $false; SailPoint = $false; PamEnabled = $false; PamVendor = '' }
    }
    # Ensure each DC group has CoHostedRoles as an array (single-element arrays
    # may be unwrapped to a plain string by PowerShell's pipeline)
    foreach ($g in $answers.DCGroups) {
        if (-not $g.ContainsKey('CoHostedRoles') -or $null -eq $g['CoHostedRoles']) {
            $g['CoHostedRoles'] = @()
        } elseif ($g['CoHostedRoles'] -is [string]) {
            $g['CoHostedRoles'] = @($g['CoHostedRoles'])
        }
    }
    return $answers
}

#endregion

#region ─── Questionnaire ────────────────────────────────────────────────────

# Each section is its own function. All take $Answers by reference (hashtable).
# The wrapper Invoke-Questionnaire loops through them and supports re-do.

function Invoke-Section1 {
    param ([hashtable] $Answers)
    Write-Section '1 / 10  —  Licensing' -SectionNum 1 -Answers $Answers
    Write-Host ''
    Write-Host '  Qualifying licenses: EMS E5/A5  ·  Microsoft 365 E5/A5/G5  ·  M365 E5/F5 Security' -ForegroundColor DarkGray
    Write-Host '                       M365 F5 Security + Compliance  ·  Standalone MDI license'       -ForegroundColor DarkGray

    $licStatus = Read-Choice `
        -Prompt 'Does the customer have a qualifying MDI license?' `
        -Options @(
            'Yes — license confirmed',
            'No — license not yet procured',
            'Unknown — needs verification'
        ) `
        -Default 1 -Recommended 1

    $Answers.Licensing.Status = $licStatus

    if ($licStatus -eq 'Yes — license confirmed') {
        $Answers.Licensing.Type = Read-Choice `
            -Prompt 'Which license type?' `
            -Options @(
                'EMS E5/A5',
                'Microsoft 365 E5/A5/G5',
                'M365 E5/A5/G5/F5 Security',
                'M365 F5 Security + Compliance',
                'Standalone MDI license',
                'Not sure'
            ) `
            -Default 2 -Recommended 2
    } else {
        $Answers.Licensing.Type = 'N/A'
    }
}

function Invoke-Section2 {
    param ([hashtable] $Answers)
    Write-Section '2 / 10  —  ATA Migration' -SectionNum 2 -Answers $Answers
    Write-Host ''
    Write-Host '  Microsoft Advanced Threat Analytics (ATA) reached end of support on January 12, 2021.' -ForegroundColor DarkGray
    Write-Host '  ATA Lightweight Gateways installed on DCs conflict with MDI sensors and must be removed first.' -ForegroundColor DarkGray

    $ataDeployed = Read-YesNo -Prompt 'Is Microsoft ATA (ATA Center / ATA Gateways / Lightweight Gateways) present in the environment?' -Default $false
    $ataStillActive = $false
    if ($ataDeployed) {
        Write-Host ''
        Write-Host '  ⚠  ATA and MDI sensors cannot coexist on the same DC. ATA must be fully decommissioned first.' -ForegroundColor Red
        $ataStillActive = Read-YesNo -Prompt 'Is ATA still actively used (not yet decommissioned)?' -Default $true
    }

    $Answers.ATA = @{
        IsDeployed  = $ataDeployed
        StillActive = $ataStillActive
    }
}

function Invoke-Section3 {
    param ([hashtable] $Answers)
    Write-Section '3 / 10  —  Forest & Domain Topology' -SectionNum 3 -Answers $Answers

    $forestCount = Read-Int -Prompt 'Number of Active Directory forests' -Min 1 -Max 100 -Default 1
    $Answers.Topology.ForestCount = $forestCount
    $Answers.Topology.DomainCount = Read-Int -Prompt 'Total number of AD domains (across all forests)' -Min 1 -Max 1000 -Default $forestCount

    $forests = [System.Collections.Generic.List[hashtable]]::new()
    if ($forestCount -gt 1) {
        for ($f = 1; $f -le $forestCount; $f++) {
            Write-SubSection "Forest $f"
            $fEntry = @{ Index = $f; TrustType = 'N/A (primary forest)' }
            if ($f -gt 1) {
                $fEntry.TrustType = Read-Choice `
                    -Prompt "Trust type between Forest $f and Forest 1" `
                    -Options $script:TrustTypes `
                    -Default 1 -Recommended 1
            }
            $forests.Add($fEntry)
        }
    } else {
        $forests.Add(@{ Index = 1; TrustType = 'N/A (primary forest)' })
    }
    $Answers.Topology.Forests = $forests
}

function Invoke-Section4 {
    param ([hashtable] $Answers)
    Write-Section '4 / 10  —  Domain Controller Inventory' -SectionNum 4 -Answers $Answers
    Write-Host ''
    Write-Host '  Describe your DCs in groups — each group shares OS version, co-hosted roles, and traffic range.' -ForegroundColor DarkGray
    Write-Host '  You do not need to enter individual server names.' -ForegroundColor DarkGray

    # Reset DC groups if re-running this section
    $Answers.DCGroups = [System.Collections.Generic.List[hashtable]]::new()

    $groupIndex = 1
    while ($true) {
        Write-SubSection "DC Group $groupIndex"
        $grp = @{}

        $grp.OSVersion = Read-Choice `
            -Prompt 'OS version' `
            -Options $script:OSVersions `
            -Default 3 -Recommended 3

        $roles = [System.Collections.Generic.List[string]]::new()
        if (Read-YesNo -Prompt 'Co-hosted AD FS role on these DCs?' -Default $false)              { $roles.Add('AD FS') }
        if (Read-YesNo -Prompt 'Co-hosted AD CS (Certification Authority) role?' -Default $false) { $roles.Add('AD CS') }
        if (Read-YesNo -Prompt 'Co-hosted Microsoft Entra Connect role?' -Default $false)          { $roles.Add('Entra Connect') }
        $grp.CoHostedRoles = @($roles)

        $grp.IsRODC        = Read-YesNo -Prompt 'Are these Read-Only Domain Controllers (RODC)?' -Default $false
        $grp.TrafficBucket = Read-Choice `
            -Prompt 'Estimated peak network traffic per DC (packets/sec)' `
            -Options $script:TrafficBuckets `
            -Default 8 -Recommended 3
        $grp.Count         = Read-Int -Prompt 'Number of DCs with this exact OS / roles / traffic profile (count of individual servers)?' -Min 1 -Max 9999 -Default 1

        $Answers.DCGroups.Add($grp)
        $groupIndex++

        Write-DCGroupTable -DCGroups $Answers.DCGroups -Answers $Answers

        # 3-way next prompt
        Write-Host ''
        Write-Host '  [Y] Add another DC group   [N] Done   [E] Edit last group' -ForegroundColor White
        Write-Host '  Choice: ' -ForegroundColor White -NoNewline
        $nav = Read-KeyChar -ValidChars @('Y','N','E')
        if ([string]::IsNullOrEmpty($nav)) { $nav = 'N' }
        Write-Host $nav -ForegroundColor Cyan

        if ($nav -eq 'N') { break }
        if ($nav -eq 'E') {
            $Answers.DCGroups.RemoveAt($Answers.DCGroups.Count - 1)
            $groupIndex--
            Write-Host '  ↩  Re-entering last group...' -ForegroundColor Yellow
        }
        # 'Y' continues loop naturally
    }
}

function Invoke-Section5 {
    param ([hashtable] $Answers)
    Write-Section '5 / 10  —  Dedicated Role Servers' -SectionNum 5 -Answers $Answers
    Write-Host ''
    Write-Host '  Dedicated domain-joined member servers running AD FS / AD CS / Entra Connect.' -ForegroundColor DarkGray
    Write-Host '  (These are NOT Domain Controllers — they are separate, domain-joined servers with a specific role.)' -ForegroundColor DarkGray

    $standalone = @{}

    Write-SubSection 'AD FS Servers (dedicated domain-joined member servers, not DCs)'
    if (Read-YesNo -Prompt 'Any dedicated AD FS federation servers (not co-hosted on DCs)?' -Default $false) {
        $standalone.ADFS = @{
            Count     = Read-Int -Prompt 'How many dedicated AD FS servers?' -Min 1 -Default 2
            OSVersion = 'N/A'
        }
    } else {
        $standalone.ADFS = @{ Count = 0; OSVersion = 'N/A' }
    }

    Write-SubSection 'AD CS Servers (dedicated domain-joined member servers, not DCs)'
    if (Read-YesNo -Prompt 'Any dedicated AD CS (Certification Authority) servers (not co-hosted on DCs)?' -Default $false) {
        $standalone.ADCS = @{
            Count     = Read-Int -Prompt 'How many dedicated AD CS servers?' -Min 1 -Default 1
            OSVersion = 'N/A'
        }
    } else {
        $standalone.ADCS = @{ Count = 0; OSVersion = 'N/A' }
    }

    Write-SubSection 'Microsoft Entra Identity Synchronisation'
    $syncTool = Read-Choice `
        -Prompt 'Which identity synchronisation tool is in use?' `
        -Options @(
            'Microsoft Entra Connect Sync (sync agent — MDI sensor required)',
            'Microsoft Entra Cloud Sync (lightweight provisioning agent — no MDI sensor needed)',
            'No identity synchronisation in use'
        ) `
        -Default 1

    $standalone['SyncTool'] = $syncTool

    if ($syncTool -like 'Microsoft Entra Connect Sync*') {
        # By design, exactly one active Entra Connect Sync server is allowed at a time
        $standalone.EntraConnectActive  = @{ Count = 1; OSVersion = 'N/A' }
        if (Read-YesNo -Prompt 'Any Entra Connect Sync servers in staging mode?' -Default $true) {
            # By design, exactly one staging server is allowed at a time
            $standalone.EntraConnectStaging = @{ Count = 1; OSVersion = 'N/A' }
        } else {
            $standalone.EntraConnectStaging = @{ Count = 0; OSVersion = 'N/A' }
        }
    } else {
        # Cloud Sync or N/A — no MDI sensor deployment required for sync servers
        $standalone.EntraConnectActive  = @{ Count = 0; OSVersion = 'N/A' }
        $standalone.EntraConnectStaging = @{ Count = 0; OSVersion = 'N/A' }
        if ($syncTool -like 'Microsoft Entra Cloud Sync*') {
            Write-Host ''
            Write-Host '  ℹ  Entra Cloud Sync uses a lightweight provisioning agent.' -ForegroundColor DarkCyan
            Write-Host '     No MDI sensor deployment is required on Cloud Sync hosts.' -ForegroundColor DarkCyan
        }
    }

    $Answers.StandaloneServers = $standalone
}

function Invoke-Section6 {
    param ([hashtable] $Answers)
    Write-Section '8 / 10  —  Connectivity' -SectionNum 8 -Answers $Answers
    Write-Host ''

    # Determine if all sensor-bearing servers are v3-eligible based on answers so far
    $vpnBlock   = $Answers.Features -and $Answers.Features['VPNIntegration']
    $sysBlock   = $Answers.Features -and $Answers.Features['SyslogNotifications']
    $mdeStatus  = if ($Answers.MDE) { $Answers.MDE['DeployedOnDCs'] } else { '' }
    $allMDE     = $mdeStatus -eq 'Yes — deployed on ALL DCs'
    $allV3Eligible = $allMDE -and -not $vpnBlock -and -not $sysBlock -and
                     ($Answers.DCGroups | ForEach-Object { $_.OSVersion } | Where-Object { $_ -notin @('Windows Server 2019','Windows Server 2022','Windows Server 2025') } | Measure-Object).Count -eq 0

    if ($allV3Eligible) {
        Write-Host '  ✔  All sensor-bearing servers are v3.x eligible.' -ForegroundColor Green
        Write-Host '     MDE streamlined connectivity is available: MDI traffic routes through the MDE channel.' -ForegroundColor DarkGray
        Write-Host '     No direct outbound access to *.atp.azure.com is required when using streamlined connectivity.' -ForegroundColor DarkGray
    } else {
        Write-Host '  v2.x sensors require outbound HTTPS (TCP 443) to *.atp.azure.com.' -ForegroundColor DarkGray
        Write-Host '  This applies to all sensor-bearing servers running v2.x: DCs, AD CS, and Entra Connect.' -ForegroundColor DarkGray
        Write-Host '  v3.x sensors do not have these requirements — connectivity is handled via the MDE integration channel.' -ForegroundColor DarkGray
    }
    Write-Host '  SSL/TLS inspection is NOT supported on MDI URLs and must be excluded.' -ForegroundColor DarkGray

    $connOptions = if ($allV3Eligible) {
        @(
            'MDE streamlined connectivity (v3.x sensors — traffic via MDE channel, no direct MDI URLs needed)',
            'Direct access to MDI backend via Internet (TLS encrypted)',
            'Forward proxy',
            'Azure ExpressRoute (Microsoft peering)',
            'Firewall with Azure IP allowlist'
        )
    } else {
        @(
            'Direct access to MDI backend via Internet (TLS encrypted)',
            'Forward proxy',
            'Azure ExpressRoute (Microsoft peering)',
            'Firewall with Azure IP allowlist'
        )
    }
    $defaultConn = 1
    $recommendedConn = 1

    $connMethod = Read-Choice `
        -Prompt 'How do sensor-bearing servers connect to the MDI backend?' `
        -Options $connOptions `
        -Default $defaultConn -Recommended $recommendedConn

    $conn = @{
        Method             = $connMethod
        ProxyUrl           = ''
        ProxyAuthRequired  = $false
        SSLInspection      = $false
    }

    if ($connMethod -eq 'Forward proxy') {
        Write-Host ''
        Write-Host '  Proxy URL (e.g. http://proxy.contoso.com:8080)' -ForegroundColor White
        Write-Host '  Leave blank to mark as TBD (can be filled in later): ' -ForegroundColor DarkGray -NoNewline
        $proxyInput = (Read-Host).Trim()
        $conn.ProxyUrl          = if ($proxyInput) { $proxyInput } else { 'TBD' }
        $conn.ProxyAuthRequired = Read-YesNo -Prompt 'Does the proxy require authentication?' -Default $false
        $conn.SSLInspection     = Read-YesNo -Prompt 'Is SSL/TLS inspection enabled on the proxy?' -Default $false
        if ($conn.SSLInspection) {
            Write-Host ''
            Write-Host '  ⚠  WARNING: SSL inspection is NOT supported by MDI sensors.' -ForegroundColor Red
            Write-Host '     MDI URLs must be excluded from SSL inspection.' -ForegroundColor Red
        }
    }

    $Answers.Connectivity = $conn
}

function Invoke-Section7 {
    param ([hashtable] $Answers)
    Write-Section '6 / 10  —  Microsoft Defender for Endpoint (MDE)' -SectionNum 6 -Answers $Answers
    Write-Host ''
    Write-Host '  Sensor v3.x requires MDE to be deployed on the Domain Controller.' -ForegroundColor DarkGray

    $mdeStatus = Read-Choice `
        -Prompt 'Is Microsoft Defender for Endpoint deployed on Domain Controllers?' `
        -Options @(
            'Yes — deployed on ALL DCs',
            'Yes — deployed on SOME DCs (mixed)',
            'No — not deployed'
        ) `
        -Default 1 -Recommended 1

    $mde = @{ DeployedOnDCs = $mdeStatus; OSVersionsWithMDE = @() }

    if ($mdeStatus -eq 'Yes — deployed on SOME DCs (mixed)') {
        Write-Host ''
        Write-Host '  Select which OS versions have MDE deployed (determines v3.x eligibility):' -ForegroundColor White
        $osWithMDE = [System.Collections.Generic.List[string]]::new()
        foreach ($os in @('Windows Server 2019', 'Windows Server 2022', 'Windows Server 2025')) {
            if (Read-YesNo -Prompt "MDE deployed on $os DCs?" -Default $false) { $osWithMDE.Add($os) }
        }
        $mde.OSVersionsWithMDE = @($osWithMDE)
    }

    $Answers.MDE = $mde
}

function Invoke-Section8 {
    param ([hashtable] $Answers)
    Write-Section '7 / 10  —  Feature Requirements' -SectionNum 7 -Answers $Answers
    Write-Host ''
    Write-Host '  Some features are not supported by sensor v3.x — they force affected DCs to v2.x.' -ForegroundColor DarkGray

    $Answers.Features = @{
        VPNIntegration      = Read-YesNo -Prompt 'Is VPN integration (RADIUS accounting) required?  [Not supported by v3.x]' -Default $false
        SyslogNotifications = Read-YesNo -Prompt 'Are syslog alert notifications required?  [Not supported by v3.x]' -Default $false
    }
}

function Invoke-Section9 {
    param ([hashtable] $Answers)
    Write-Section '9 / 10  —  Directory Service Account (DSA)' -SectionNum 9 -Answers $Answers
    Write-Host ''
    Write-Host '  The DSA is used by MDI sensors to query Active Directory (LDAP, DeletedObjects).' -ForegroundColor DarkGray
    Write-Host '  gMSA is recommended — Active Directory manages password rotation automatically.'          -ForegroundColor DarkGray

    $dsaType = Read-Choice `
        -Prompt 'Preferred DSA account type' `
        -Options @(
            'Group Managed Service Account (gMSA)',
            'Regular AD user account'
        ) `
        -Default 1 -Recommended 1

    $kdsRootKeyExists = $false
    if ($dsaType -like '*gMSA*') {
        Write-Host ''
        Write-Host '  The KDS Root Key is required to create gMSA accounts. It only needs to be created once per forest.' -ForegroundColor DarkGray
        Write-Host '  If gMSA accounts already exist in the domain, the KDS Root Key is already present.' -ForegroundColor DarkGray
        $kdsRootKeyExists = Read-YesNo -Prompt 'Is a KDS Root Key already present in the forest (i.e. gMSA accounts are already in use)?' -Default $true
    }

    $forestCount = $Answers.Topology['ForestCount']
    $Answers.DSA = @{
        Type             = $dsaType
        KdsRootKeyExists = $kdsRootKeyExists
        PerForest        = $(if ($forestCount -gt 1) {
            Read-YesNo -Prompt 'Create a separate DSA per forest?' -Default $true
        } else { $false })
    }
}

# ── Section 10: Identity & PAM Integrations ──────────────────────────────────
function Invoke-Section10 {
    param ([hashtable] $Answers)
    Write-Section '10 / 10  —  Identity & PAM Integrations (Optional)' -SectionNum 10 -Answers $Answers
    Write-Host ''
    Write-Host '  MDI can integrate with third-party identity and PAM platforms to extend' -ForegroundColor DarkGray
    Write-Host '  its visibility and remediation capabilities into those systems.'          -ForegroundColor DarkGray
    Write-Host '  All integrations are optional and configured post-deployment via'        -ForegroundColor DarkGray
    Write-Host '  Defender portal > System > Data Management > Data Connectors.'           -ForegroundColor DarkGray

    # ── Okta ─────────────────────────────────────────────────────────────────
    Write-Host ''
    Write-Host '  ► Okta Single Sign-On / IAM' -ForegroundColor Yellow
    Write-Host '    Adds Okta users to the identity inventory, surfaces posture'       -ForegroundColor DarkGray
    Write-Host '    recommendations, raises alerts on suspicious Okta activity, and'   -ForegroundColor DarkGray
    Write-Host '    enables remediation actions (revoke sessions, deactivate user).'   -ForegroundColor DarkGray
    Write-Host '    Requires: Okta Developer or Enterprise license + Super Admin role' -ForegroundColor DarkGray
    Write-Host '    (Super Admin is needed only during setup — can be removed after).' -ForegroundColor DarkGray
    $useOkta = Read-YesNo -Prompt 'Does the organization use Okta as an Identity Provider?' -Default $false

    $oktaAlreadyMDA = $false
    if ($useOkta) {
        Write-Host ''
        Write-Host '    ⚠  NOTE: If Okta is already connected to Microsoft Defender for'  -ForegroundColor Yellow
        Write-Host '       Cloud Apps (MDA), duplicate Okta activity data will appear in'  -ForegroundColor Yellow
        Write-Host '       the Defender portal after also connecting it to MDI.'            -ForegroundColor Yellow
        $oktaAlreadyMDA = Read-YesNo -Prompt '    Is Okta already connected to Microsoft Defender for Cloud Apps (MDA)?' -Default $false
    }

    # ── CyberArk Identity (SaaS) ──────────────────────────────────────────────
    Write-Host ''
    Write-Host '  ► CyberArk Identity (SaaS / Cloud PAM)  [Preview]' -ForegroundColor Yellow
    Write-Host '    Adds CyberArk Identity accounts to the identity inventory (including'  -ForegroundColor DarkGray
    Write-Host '    AD accounts managed as PAM accounts), surfaces posture recommendations' -ForegroundColor DarkGray
    Write-Host '    and enables remediation actions (disable/enable user, reset PAM pwd).'  -ForegroundColor DarkGray
    Write-Host '    Requires: CyberArk Identity System Admin role to create the OAuth app.' -ForegroundColor DarkGray
    $useCyberArkId = Read-YesNo -Prompt 'Does the organization use CyberArk Identity (SaaS)?' -Default $false

    # ── SailPoint Identity Security Cloud ────────────────────────────────────
    Write-Host ''
    Write-Host '  ► SailPoint Identity Security Cloud (IGA)  [Preview]' -ForegroundColor Yellow
    Write-Host '    Adds SailPoint accounts to the identity inventory, surfaces posture'   -ForegroundColor DarkGray
    Write-Host '    recommendations, and enables remediation actions (disable/enable user).' -ForegroundColor DarkGray
    Write-Host '    Requires: SailPoint IdentityNow Admin role to create the PAT.'          -ForegroundColor DarkGray
    $useSailPoint = Read-YesNo -Prompt 'Does the organization use SailPoint Identity Security Cloud?' -Default $false

    # ── PAM Services (on-prem / API-level integration) ─────────────────────
    Write-Host ''
    Write-Host '  ► PAM Services Integration (CyberArk PAM / BeyondTrust / Delinea)' -ForegroundColor Yellow
    Write-Host '    Tags PAM-managed identities in Defender XDR for investigation context'   -ForegroundColor DarkGray
    Write-Host '    and enables direct password reset from the Defender portal.'              -ForegroundColor DarkGray
    Write-Host '    Supported vendors: CyberArk PAM, BeyondTrust, Delinea.'                 -ForegroundColor DarkGray
    Write-Host '    Setup is done via the vendor-specific integration guide (not a Defender' -ForegroundColor DarkGray
    Write-Host '    portal connector — configuration happens on the vendor side).'           -ForegroundColor DarkGray
    $usePam = Read-YesNo -Prompt 'Does the organization use a PAM solution (CyberArk PAM, BeyondTrust, or Delinea)?' -Default $false

    $pamVendor = ''
    if ($usePam) {
        $pamVendor = Read-Choice `
            -Prompt 'Which PAM vendor?' `
            -Options @(
                'CyberArk PAM (Privileged Cloud or Self-Hosted)',
                'BeyondTrust',
                'Delinea',
                'Other / Not yet decided'
            ) `
            -Default 1
    }

    $Answers.Integrations = @{
        Okta           = $useOkta
        OktaAlreadyMDA = $oktaAlreadyMDA
        CyberArkId     = $useCyberArkId
        SailPoint      = $useSailPoint
        PamEnabled     = $usePam
        PamVendor      = $pamVendor
    }
}

# ── Review screen after all 9 sections ───────────────────────────────────────
function Show-ReviewScreen {
    param ([hashtable] $Answers)

    Clear-Host
    Write-Host ''
    Write-Host '  ╔═══════════════════════════════════════════════════════════════════╗' -ForegroundColor Cyan
    Write-Host '  ║              MDI Deployment Planner — Review Answers             ║' -ForegroundColor Cyan
    Write-Host '  ╚═══════════════════════════════════════════════════════════════════╝' -ForegroundColor Cyan
    Write-Host ''

    $sections = @(
        @{ Num = 1;  Key = '1'; Name = 'Licensing';          Value = { "$($Answers.Licensing['Status'])" + $(if ($Answers.Licensing['Type'] -and $Answers.Licensing['Type'] -ne 'N/A') { " — $($Answers.Licensing['Type'])" } else { '' }) } }
        @{ Num = 2;  Key = '2'; Name = 'ATA Migration';      Value = { if ($Answers.ATA['IsDeployed']) { if ($Answers.ATA['StillActive']) { 'Present — ACTIVE (blocker)' } else { 'Present — decommissioned' } } else { 'Not deployed' } } }
        @{ Num = 3;  Key = '3'; Name = 'Forest & Domain';    Value = { "$($Answers.Topology['ForestCount']) forest(s) · $($Answers.Topology['DomainCount']) domain(s)" } }
        @{ Num = 4;  Key = '4'; Name = 'DC Inventory';       Value = { $t = 0; foreach ($g in $Answers.DCGroups) { $t += [int]$g['Count'] }; "$($Answers.DCGroups.Count) group(s) · $t DC(s)" } }
        @{ Num = 5;  Key = '5'; Name = 'Standalone Servers'; Value = { $s = 0; foreach ($k in @('ADFS','ADCS','EntraConnectActive','EntraConnectStaging')) { if ($Answers.StandaloneServers[$k]) { $s += [int]$Answers.StandaloneServers[$k]['Count'] } }; "$s server(s)" } }
        @{ Num = 6;  Key = '6'; Name = 'MDE';                Value = { $Answers.MDE['DeployedOnDCs'] -replace '^Yes — deployed on ALL DCs$','All DCs' -replace '^Yes — deployed on SOME DCs \(mixed\)$','Mixed' -replace '^No — not deployed$','Not deployed' } }
        @{ Num = 7;  Key = '7'; Name = 'Feature Reqs';       Value = { $f = @(); if ($Answers.Features['VPNIntegration']) { $f += 'VPN' }; if ($Answers.Features['SyslogNotifications']) { $f += 'Syslog' }; if ($f) { "Required: $($f -join ', ') (→ v2.x)" } else { 'No v3.x-blocking features' } } }
        @{ Num = 8;  Key = '8'; Name = 'Connectivity';       Value = { $m = $Answers.Connectivity['Method'] -replace '^MDE streamlined.*$','MDE streamlined' -replace '^Direct access.*$','Direct' -replace '^Forward proxy$','Forward proxy' -replace '^Azure ExpressRoute.*$','ExpressRoute' -replace '^Firewall.*$','Firewall + allowlist'; if ($Answers.Connectivity['SSLInspection']) { "$m  ⚠ SSL inspection!" } else { $m } } }
        @{ Num = 9;  Key = '9'; Name = 'DSA';                Value = { $Answers.DSA['Type'] -replace '^Group Managed Service Account \(gMSA\).*$','gMSA (recommended)' -replace '^Regular AD user account$','Regular AD account' } }
        @{ Num = 10; Key = '0'; Name = 'Integrations';       Value = {
            $p = [System.Collections.Generic.List[string]]::new()
            if ($Answers.Integrations['Okta'])       { $p.Add('Okta') }
            if ($Answers.Integrations['CyberArkId']) { $p.Add('CyberArk Identity') }
            if ($Answers.Integrations['SailPoint'])  { $p.Add('SailPoint') }
            if ($Answers.Integrations['PamEnabled']) { $p.Add("PAM ($($Answers.Integrations['PamVendor'] -replace ' .*$',''))") }
            if ($p.Count -gt 0) { $p -join ', ' } else { 'None selected' }
        } }
    )

    $incompleteCount = 0
    foreach ($s in $sections) {
        $val = & $s.Value
        if ([string]::IsNullOrWhiteSpace($val)) {
            $incompleteCount++
            Write-Host ("  [{0}] {1,-24} " -f $s.Key, $s.Name) -ForegroundColor Gray -NoNewline
            Write-Host '⚠  not answered — press the number to complete' -ForegroundColor Yellow
        } else {
            Write-Host ("  [{0}] {1,-24} {2}" -f $s.Key, $s.Name, $val) -ForegroundColor Gray
        }
    }

    Write-Host ''
    Write-Host '  ─────────────────────────────────────────────────────────────────────' -ForegroundColor DarkGray
    if ($incompleteCount -gt 0) {
        Write-Host "  ⚠  $incompleteCount section(s) incomplete — answer them before pressing [G]." -ForegroundColor Yellow
    }
    Write-Host '  Press [G] to generate report, [1]–[9] to re-run a section, [0] for section 10.' -ForegroundColor White
    Write-Host '  Choice: ' -ForegroundColor White -NoNewline

    $ch = Read-KeyChar -ValidChars @('G','1','2','3','4','5','6','7','8','9','0')
    if ([string]::IsNullOrEmpty($ch)) { $ch = 'G' }
    Write-Host $ch -ForegroundColor Cyan
    return $ch
}

# ── Main questionnaire wrapper ────────────────────────────────────────────────
function Invoke-Questionnaire {
    param (
        [string]    $CustomerName,
        [hashtable] $LoadedAnswers,
        [string]    $OutputPath
    )

    if ($LoadedAnswers) {
        $answers = $LoadedAnswers
    } else {
        $answers = @{
            CustomerName      = $CustomerName
            GeneratedAt       = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            Licensing         = @{}
            Topology          = @{}
            DCGroups          = [System.Collections.Generic.List[hashtable]]::new()
            StandaloneServers = @{}
            Connectivity      = @{}
            MDE               = @{}
            Features          = @{}
            DSA               = @{}
            ATA               = @{}
            Integrations      = @{}
        }
    }

    $sectionFns = @{
        1 = { Invoke-Section1 -Answers $answers }
        2 = { Invoke-Section2 -Answers $answers }
        3 = { Invoke-Section3 -Answers $answers }
        4 = { Invoke-Section4 -Answers $answers }
        5 = { Invoke-Section5 -Answers $answers }
        6 = { Invoke-Section7 -Answers $answers }
        7 = { Invoke-Section8 -Answers $answers }
        8 = { Invoke-Section6 -Answers $answers }
        9 = { Invoke-Section9 -Answers $answers }
        10 = { Invoke-Section10 -Answers $answers }
    }

    if (-not $LoadedAnswers) {
        # Run all 10 sections in order; auto-save draft after each
        for ($i = 1; $i -le 10; $i++) {
            & $sectionFns[$i]
            if ($OutputPath) { Save-DraftPlan -Answers $answers -OutputPath $OutputPath }
        }
    }

    # Review + re-do loop
    while ($true) {
        $choice = Show-ReviewScreen -Answers $answers
        if ($choice -eq 'G') {
            # Safety check — ensure all required sections have been answered
            $missing = @()
            if (-not $answers.Licensing['Status'])                                 { $missing += '[1] Licensing' }
            if (-not $answers.ATA -or $answers.ATA.Count -eq 0)                   { $missing += '[2] ATA Migration' }
            if (-not $answers.Topology['ForestCount'])                             { $missing += '[3] Forest & Domain' }
            if (-not $answers.DCGroups -or $answers.DCGroups.Count -eq 0)         { $missing += '[4] DC Inventory' }
            if (-not $answers.StandaloneServers -or $answers.StandaloneServers.Count -eq 0) { $missing += '[5] Standalone Servers' }
            if (-not $answers.MDE['DeployedOnDCs'])                                { $missing += '[6] MDE' }
            if (-not $answers.Connectivity['Method'])                              { $missing += '[8] Connectivity' }
            if (-not $answers.DSA['Type'])                                         { $missing += '[9] DSA' }
            if ($missing.Count -gt 0) {
                Write-Host ''
                Write-Host '  ⚠  Cannot generate — the following sections are incomplete:' -ForegroundColor Red
                foreach ($m in $missing) { Write-Host "       $m" -ForegroundColor Yellow }
                Write-Host '  Re-run those sections first, then press [G] again.' -ForegroundColor DarkGray
                Write-Host ''
                Write-Host '  Press any key to return to review...' -ForegroundColor DarkGray
                $null = Read-KeyChar -ValidChars @()
                continue
            }
            break
        }
        # '0' maps to section 10 (single-keypress limitation)
        $sectionNum = if ($choice -eq '0') { 10 } else { [int]$choice }
        & $sectionFns[$sectionNum]
        if ($OutputPath) { Save-DraftPlan -Answers $answers -OutputPath $OutputPath }
    }

    return $answers
}

# Auto-save current answers as a draft JSON after each completed section
function Save-DraftPlan {
    param ($Answers, [string] $OutputPath)
    if ([string]::IsNullOrWhiteSpace($Answers.CustomerName)) { return }
    if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
    $safeName = Get-SafeName -Name $Answers.CustomerName
    $filePath = Join-Path $OutputPath "MDIDeploymentPlan-${safeName}-DRAFT.json"
    @{
        Meta    = @{ SavedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'); CustomerName = $Answers.CustomerName
                     GeneratedBy = 'Invoke-MDIDeploymentPlanner.ps1'; SchemaVersion = '1.0'; IsDraft = $true }
        Answers = $Answers
    } | ConvertTo-Json -Depth 10 | Set-Content -Path $filePath -Encoding utf8
}

#endregion

#region ─── Logic Engine ─────────────────────────────────────────────────────

function Get-SensorRecommendation {
    param ($Group, $Answers, [switch] $IsStandalone)

    if ($IsStandalone) { return 'v2.x' }
    if ($Answers.Features['VPNIntegration'])       { return 'v2.x' }
    if ($Answers.Features['SyslogNotifications'])  { return 'v2.x' }
    if ($Group.OSVersion -in @('Windows Server 2016', 'Other / Legacy')) { return 'v2.x' }

    $mdeStatus  = $Answers.MDE['DeployedOnDCs']
    $mdeOK = switch ($mdeStatus) {
        'Yes — deployed on ALL DCs'           { $true }
        'Yes — deployed on SOME DCs (mixed)'  { $Group.OSVersion -in $Answers.MDE['OSVersionsWithMDE'] }
        default                               { $false }
    }

    return $(if ($mdeOK) { 'v3.x' } else { 'v2.x' })
}

function Get-SizingEstimate {
    param ([string] $TrafficBucket)
    return $script:SizingTable[$TrafficBucket]
}

function Get-DSARequirements {
    param ($Answers)

    $forestCount = $Answers.Topology['ForestCount']
    if ($forestCount -le 1) {
        return @{ Count = 1; Notes = 'Single forest — one DSA covers all domains.' }
    }

    $untrusted = @($Answers.Topology['Forests'] | Where-Object {
        $_.TrustType -in @('Non-Kerberos trust', 'No trust')
    })
    $count  = 1 + $untrusted.Count
    $notes  = "Multi-forest environment. One DSA covers forests with two-way Kerberos trust. "
    $notes += "$($untrusted.Count) additional DSA credential(s) required for non-Kerberos/untrusted forest(s)."
    if ($count -gt 30) { $notes += " WARNING: Exceeds default limit of 30 — contact MDI support." }

    return @{ Count = $count; Notes = $notes }
}

function Get-AuditingApproach {
    param ($ServerGroups)

    $hasV2 = $false; $hasV3 = $false
    foreach ($sg in $ServerGroups) {
        if ($sg['SensorVersion'] -eq 'v2.x') { $hasV2 = $true }
        if ($sg['SensorVersion'] -eq 'v3.x') { $hasV3 = $true }
    }

    if ($hasV3 -and -not $hasV2) {
        return @{
            Approach    = 'Automatic (recommended for v3.x-only environments)'
            Description = 'Enable Automatic Windows auditing in the Microsoft Defender portal: Settings > Identities > Advanced features > Automatic Windows auditing configuration. The sensor applies and maintains all required audit policies automatically every 24 hours.'
            PS          = $null
        }
    }

    return @{
        Approach    = 'PowerShell — DefenderForIdentity module (recommended for v2.x or mixed environments)'
        Description = 'Use the DefenderForIdentity PowerShell module to apply all required audit settings via Group Policy. This method works for both v2.x and v3.x sensors and provides a configuration report before applying changes.'
        PS          = 'Set-MDIConfiguration -Mode Domain -Configuration All'
    }
}

function Build-ServerGroups {
    param ($Answers)

    $groups = [System.Collections.Generic.List[hashtable]]::new()

    # DC groups
    foreach ($g in $Answers.DCGroups) {
        $sensorVer = Get-SensorRecommendation -Group $g -Answers $Answers
        $sizing    = Get-SizingEstimate -TrafficBucket $g.TrafficBucket

        $notes = [System.Collections.Generic.List[string]]::new()
        if ($g.IsRODC) { $notes.Add('RODC — supported') }
        if ($g.TrafficBucket -eq 'Unknown') {
            if ($sensorVer -eq 'v3.x') {
                $notes.Add('Version 3 of the sensor prevents the sensor from overusing CPU or memory by limiting CPU utilization at 30%, and memory usage to 1.5 GB. However, if any other service uses substantial system resources, the domain controller might still experience performance strain.')
            } else {
                $notes.Add('Run MDI Sizing Tool before installation')
            }
        }

        if ($sensorVer -eq 'v2.x' -and $g.OSVersion -in @('Windows Server 2019','Windows Server 2022','Windows Server 2025')) {
            if ($Answers.Features['VPNIntegration'])      { $notes.Add('v3 blocked: VPN integration required') }
            if ($Answers.Features['SyslogNotifications']) { $notes.Add('v3 blocked: syslog required') }
            $mde = $Answers.MDE['DeployedOnDCs']
            if ($mde -eq 'No — not deployed') {
                $notes.Add('v3 blocked: MDE not deployed')
            } elseif ($mde -eq 'Yes — deployed on SOME DCs (mixed)' -and $g.OSVersion -notin $Answers.MDE['OSVersionsWithMDE']) {
                $notes.Add('v3 blocked: MDE not deployed on this OS version')
            }
        }

        $rolesStr = if ($g.CoHostedRoles -and $g.CoHostedRoles.Count -gt 0) { "AD DS, $($g.CoHostedRoles -join ', ')" } else { 'AD DS' }

        $groups.Add(@{
            Type          = 'DC'
            OSVersion     = $g.OSVersion
            Roles         = $g.CoHostedRoles
            RolesStr      = $rolesStr
            IsRODC        = $g.IsRODC
            Traffic       = $g.TrafficBucket
            Count         = $g['Count']
            SensorVersion = $sensorVer
            SizingCPU     = $(if ($sizing) { $sizing.CPU } else { 'TBD' })
            SizingRAM     = $(if ($sizing) { $sizing.RAM } else { 'TBD' })
            Notes         = ($notes -join '; ')
        })
    }

    # Standalone servers (always v2.x)
    $standaloneTypes = @(
        @{ Key = 'ADFS';               Label = 'AD FS (standalone)';      Roles = @('AD FS') }
        @{ Key = 'ADCS';               Label = 'AD CS (standalone)';      Roles = @('AD CS') }
        @{ Key = 'EntraConnectActive';  Label = 'Entra Connect (Active)';  Roles = @('Entra Connect') }
        @{ Key = 'EntraConnectStaging'; Label = 'Entra Connect (Staging)'; Roles = @('Entra Connect') }
    )

    foreach ($st in $standaloneTypes) {
        $srv = $Answers.StandaloneServers[$st.Key]
        if ($srv['Count'] -gt 0) {
            $groups.Add(@{
                Type          = 'Standalone'
                OSVersion     = 'WS 2016 or later (v2.x)'
                Roles         = $st.Roles
                RolesStr      = $st.Label
                IsRODC        = $false
                Traffic       = 'Role-based'
                Count         = $srv['Count']
                SensorVersion = 'v2.x'
                SizingCPU     = 'Minimal'
                SizingRAM     = 'Minimal'
                Notes         = 'Standalone role server — sensor v2.x required; DSA mandatory'
            })
        }
    }

    return $groups
}

function Get-Warnings {
    param ($Answers, $ServerGroups)

    $warnings = [System.Collections.Generic.List[hashtable]]::new()

    if ($Answers.Licensing['Status'] -ne 'Yes — license confirmed') {
        $warnings.Add(@{
            Severity = 'BLOCKER'
            Message  = 'MDI licensing is not confirmed. Deployment cannot proceed until a qualifying license is assigned to all in-scope users.'
            RefUrl   = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/prerequisites-sensor-version-2#licensing-requirements'
        })
    }

    if ($Answers.Connectivity['SSLInspection']) {
        $warnings.Add(@{
            Severity = 'BLOCKER'
            Message  = 'SSL/TLS inspection is enabled on the proxy. MDI sensors use certificate-based mutual authentication — SSL inspection will break connectivity. The MDI sensor API URL must be excluded from inspection.'
            RefUrl   = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-proxy'
        })
    }

    $hasLegacy = $false; $unknownV2Sizing = 0; $totalSensors = 0
    foreach ($sg in $ServerGroups) {
        if ($sg['OSVersion'] -eq 'Other / Legacy')                                                           { $hasLegacy = $true }
        if ($sg['Type'] -eq 'DC' -and $sg['Traffic'] -eq 'Unknown' -and $sg['SensorVersion'] -eq 'v2.x') { $unknownV2Sizing++ }
        $totalSensors += [int]$sg['Count']
    }
    if ($hasLegacy) {
        $warnings.Add(@{
            Severity = 'WARNING'
            Message  = "One or more DC groups use 'Other / Legacy' OS. MDI requires Windows Server 2016 or later. Servers running Windows Server 2012/2012 R2 have limited sensor functionality and should be upgraded before deployment."
            RefUrl   = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/prerequisites-sensor-version-2#minimum-operating-system-requirements'
        })
    }
    if ($unknownV2Sizing -gt 0) {
        $warnings.Add(@{
            Severity = 'WARNING'
            Message  = "$unknownV2Sizing DC group(s) with v2.x sensor have unknown network traffic. Run the MDI Sizing Tool (TriSizingTool.exe) on all affected DCs before sensor installation to confirm sufficient CPU and RAM."
            RefUrl   = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/capacity-planning'
        })
    }

    $dsaReqs = Get-DSARequirements -Answers $Answers
    if ($dsaReqs['Count'] -gt 30) {
        $warnings.Add(@{
            Severity = 'WARNING'
            Message  = "Calculated DSA credential count ($($dsaReqs['Count'])) exceeds the default workspace limit of 30. Contact Microsoft Defender for Identity support before deployment."
            RefUrl   = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/multi-forest'
        })
    }
    if ($totalSensors -gt 350) {
        $warnings.Add(@{
            Severity = 'WARNING'
            Message  = "Total sensor count ($totalSensors) exceeds the default limit of 350 per workspace. Contact Microsoft Defender for Identity support to confirm support for your scale."
            RefUrl   = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/capacity-planning'
        })
    }

    if ($Answers.Features['VPNIntegration']) {
        $warnings.Add(@{
            Severity = 'INFO'
            Message  = 'VPN integration (RADIUS accounting) is required. Sensor v3.x does not support VPN integration — all DCs requiring VPN integration will be deployed with sensor v2.x.'
            RefUrl   = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/deploy-defender-identity#select-your-deployment-method'
        })
    }

    if ($Answers.Features['SyslogNotifications']) {
        $warnings.Add(@{
            Severity = 'INFO'
            Message  = 'Syslog notifications are required. Sensor v3.x does not support syslog — affected DCs will use sensor v2.x.'
            RefUrl   = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/deploy-defender-identity#select-your-deployment-method'
        })
    }

    # Identity & PAM Integration advisories — only surface the Okta/MDA duplicate as a WARNING;
    # all other integration notes live in the dedicated Planned Integrations section of the report.
    $integrations = $Answers.Integrations
    if ($integrations -and $integrations['Okta'] -and $integrations['OktaAlreadyMDA']) {
        $warnings.Add(@{
            Severity = 'WARNING'
            Message  = 'Okta is already connected to Microsoft Defender for Cloud Apps (MDA). Connecting MDI will cause duplicate Okta activity data to appear in the Defender portal. Review both connectors after setup — consider removing the MDA Okta connector to avoid duplicates.'
            RefUrl   = 'https://learn.microsoft.com/en-us/defender-for-identity/okta-integration'
        })
    }

    if ($Answers.Connectivity['Method'] -eq 'Forward proxy' -and
        ($Answers.Connectivity['ProxyUrl'] -eq 'TBD' -or -not $Answers.Connectivity['ProxyUrl'])) {
        $warnings.Add(@{
            Severity = 'WARNING'
            Message  = 'Proxy URL was not provided (marked as TBD). The proxy URL must be configured in the MDI sensor settings before deployment. Update this plan and the sensor configuration once the URL is known.'
            RefUrl   = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-proxy'
        })
    }

    if ($Answers.Connectivity['Method'] -eq 'Firewall with Azure IP allowlist') {
        $warnings.Add(@{
            Severity = 'INFO'
            Message  = 'Firewall with Azure IP allowlist is selected. The AzureAdvancedThreatProtection service tag IP ranges change periodically. Establish a process to regularly review and update firewall rules.'
            RefUrl   = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/prerequisites-sensor-version-2#connectivity-requirements'
        })
    }

    if ($Answers.ATA['IsDeployed']) {
        if ($Answers.ATA['StillActive']) {
            $warnings.Add(@{
                Severity = 'BLOCKER'
                Message  = 'Microsoft ATA is active in this environment. ATA Lightweight Gateways on DCs are incompatible with MDI sensors — they cannot coexist. Before deploying MDI: (1) document all ATA config and open alerts (not migrated), (2) uninstall all ATA Gateways from DCs and gateway servers, then (3) decommission the ATA Center. See Phase 0 checklist for the full ordered steps.'
                RefUrl   = 'https://learn.microsoft.com/en-us/defender-for-identity/migrate-from-ata-overview'
            })
        } else {
            $warnings.Add(@{
                Severity = 'WARNING'
                Message  = 'ATA was previously deployed in this environment. Verify that all ATA Lightweight Gateway and ATA Full Gateway services have been fully uninstalled from all DCs and gateway servers before deploying MDI sensors.'
                RefUrl   = 'https://learn.microsoft.com/en-us/defender-for-identity/migrate-from-ata-overview'
            })
        }
    }

    return $warnings
}

function Build-DeploymentChecklist {
    param ($Answers, $ServerGroups, $DSAReqs, $AuditApproach)

    $items   = [System.Collections.Generic.List[hashtable]]::new()

    $hasV2 = $false; $hasV2DC = $false; $hasV3 = $false
    $hasADFS = $false; $hasADCS = $false; $hasEC = $false; $unknownSizing = $false
    foreach ($sg in $ServerGroups) {
        if ($sg['SensorVersion'] -eq 'v2.x')                                                           { $hasV2 = $true }
        if ($sg['Type'] -eq 'DC' -and $sg['SensorVersion'] -eq 'v2.x')                                { $hasV2DC = $true }
        if ($sg['SensorVersion'] -eq 'v3.x')                                                           { $hasV3 = $true }
        if ('AD FS' -in $sg['Roles'])                                                                  { $hasADFS = $true }
        if ('AD CS' -in $sg['Roles'])                                                                  { $hasADCS = $true }
        if ('Entra Connect' -in $sg['Roles'])                                                          { $hasEC = $true }
        if ($sg['Type'] -eq 'DC' -and $sg['Traffic'] -eq 'Unknown' -and $sg['SensorVersion'] -eq 'v2.x') { $unknownSizing = $true }
    }

    $isMultiForest   = $Answers.Topology['ForestCount'] -gt 1
    $hasProxy        = $Answers.Connectivity['Method'] -eq 'Forward proxy'
    $hasExpressRoute = $Answers.Connectivity['Method'] -eq 'Azure ExpressRoute (Microsoft peering)'
    $hasFirewallIP   = $Answers.Connectivity['Method'] -eq 'Firewall with Azure IP allowlist'
    $useGMSA         = $Answers.DSA['Type'] -like '*gMSA*'
    $licenseOK       = $Answers.Licensing['Status'] -eq 'Yes — license confirmed'
    $hasATA          = $Answers.ATA['IsDeployed']
    $allV3           = $hasV3 -and -not $hasV2   # all sensors are v3.x — DSA not supported

    # Phase 0: ATA Decommission
    if ($hasATA -and $Answers.ATA['StillActive']) {
        # Pre-migration planning
        $items.Add(@{ Phase = 'Phase 0: ATA Migration'; Action = 'Document all existing ATA configuration before starting — collect: DSA account details, syslog notification settings, email notification details, ATA role group memberships, VPN integration details, alert exclusions (not transferable to MDI — must be recreated manually), entity tags, list of manually tagged Sensitive entities, and report schedules'; Scope = 'ATA Center'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/migrate-from-ata-overview#plan-your-migration' })
        $items.Add(@{ Phase = 'Phase 0: ATA Migration'; Action = 'Record or remediate all open ATA security alerts — ATA alerts are NOT imported or migrated to Defender for Identity; any unresolved alerts will be lost after decommission'; Scope = 'ATA Center'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/migrate-from-ata-overview#post-migration-activities' })
        $items.Add(@{ Phase = 'Phase 0: ATA Migration'; Action = 'Back up the ATA MongoDB database if you need to retain historical alert data indefinitely (optional, but recommended before decommissioning the ATA Center)'; Scope = 'ATA Center server'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/migrate-from-ata-overview#post-migration-activities' })
        # Uninstall order — gateways first, center last (per Microsoft caution)
        $items.Add(@{ Phase = 'Phase 0: ATA Migration'; Action = '⚠ BLOCKER — Step 1: Uninstall all ATA Lightweight Gateways from every Domain Controller before touching the ATA Center. Go to Control Panel > Programs > Microsoft ATA Gateway > Uninstall on each DC. Caution: uninstalling the ATA Center while gateways are still running leaves the environment unprotected.'; Scope = 'All DCs with ATA Lightweight Gateway'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/migrate-from-ata-overview#move-to-defender-for-identity' })
        $items.Add(@{ Phase = 'Phase 0: ATA Migration'; Action = '⚠ BLOCKER — Step 2: Uninstall all standalone ATA Full Gateways (if any) from dedicated gateway servers'; Scope = 'ATA Full Gateway servers'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/migrate-from-ata-overview#move-to-defender-for-identity' })
        $items.Add(@{ Phase = 'Phase 0: ATA Migration'; Action = '⚠ BLOCKER — Step 3: Uninstall the ATA Center only after all gateways have been removed. We recommend keeping the ATA Center server online (but the service stopped) for a period of time so historical data remains accessible for ongoing investigations.'; Scope = 'ATA Center server'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/migrate-from-ata-overview#post-migration-activities' })
        # Post-migration / validation (appear after MDI sensors are deployed)
        $items.Add(@{ Phase = 'Phase 6: Validation'; Action = 'Allow up to 2 hours after first MDI sensor is online for the initial ATA → MDI sync to complete before running validation tasks'; Scope = 'Defender XDR Portal'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/migrate-from-ata-overview#validate-your-migration' })
        $items.Add(@{ Phase = 'Phase 6: Validation'; Action = 'Recreate ATA alert exclusions in Microsoft Defender XDR (Settings > Identities > Exclusions) — exclusions are not carried over automatically from ATA'; Scope = 'Defender XDR Portal'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/exclusions' })
        $items.Add(@{ Phase = 'Phase 6: Validation'; Action = 'Recreate Sensitive entity tags in Microsoft Defender XDR — entity tags are not migrated from ATA'; Scope = 'Defender XDR Portal'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/entity-tags' })
    } elseif ($hasATA) {
        $items.Add(@{ Phase = 'Phase 1: Pre-Deployment'; Action = 'Verify ATA decommission is complete — confirm the Microsoft ATA Gateway service no longer exists on any DC or gateway server before installing MDI sensors'; Scope = 'All former ATA servers'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/migrate-from-ata-overview'; CmdLine = 'Get-Service -ComputerName <DC> -Name "Microsoft ATA Gateway" -ErrorAction SilentlyContinue'; CmdLineRefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/migrate-from-ata-overview' })
    }

    # Phase 1: Pre-Deployment
    if (-not $licenseOK) {
        $items.Add(@{ Phase = 'Phase 1: Pre-Deployment'; Action = 'Procure and assign Microsoft Defender for Identity licenses to all in-scope users'; Scope = 'Tenant'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/prerequisites-sensor-version-2#licensing-requirements' })
    }
    $items.Add(@{ Phase = 'Phase 1: Pre-Deployment'; Action = 'Assign Security Administrator role in Microsoft Entra ID to the deployment account'; Scope = 'Tenant'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/role-groups' })
    $items.Add(@{ Phase = 'Phase 1: Pre-Deployment'; Action = 'Install the DefenderForIdentity PowerShell module on the management workstation'; Scope = 'Management workstation'; RefUrl = 'https://www.powershellgallery.com/packages/DefenderForIdentity/'; CmdLine = 'Install-Module DefenderForIdentity -Scope CurrentUser'; CmdLineRefUrl = 'https://learn.microsoft.com/en-us/powershell/module/defenderforidentity/?view=defenderforidentity-latest' })
    if ($hasV3) {
        $items.Add(@{ Phase = 'Phase 1: Pre-Deployment'; Action = 'Confirm Microsoft Defender for Endpoint (MDE) is deployed on all v3.x target DCs'; Scope = 'v3.x DCs'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/prerequisites-sensor-version-3' })
        $items.Add(@{ Phase = 'Phase 1: Pre-Deployment'; Action = 'Verify March 2026 or later cumulative update is installed on all v3.x target DCs'; Scope = 'v3.x DCs'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/prerequisites-sensor-version-3' })
    }
    if ($unknownSizing) {
        $items.Add(@{ Phase = 'Phase 1: Pre-Deployment'; Action = 'Run MDI Sizing Tool (TriSizingTool.exe) on DCs with unknown traffic BEFORE sensor installation — required for v2.x sensors only; v3.x sensors manage their own resource usage and do not require pre-deployment sizing'; Scope = 'v2.x DCs with unknown traffic'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/capacity-planning' })
    }
    $items.Add(@{ Phase = 'Phase 1: Pre-Deployment'; Action = 'Run Test-MdiReadiness.ps1 from a management workstation — queries all DCs, CA servers, and Entra Connect servers remotely and generates an HTML + JSON readiness report. Available from Defender portal: Settings > Identities > Tools, or GitHub.'; Scope = 'Management workstation'; RefUrl = 'https://github.com/microsoft/Microsoft-Defender-for-Identity/tree/main/Test-MdiReadiness'; CmdLine = '.\Test-MdiReadiness.ps1'; CmdLineRefUrl = 'https://github.com/microsoft/Microsoft-Defender-for-Identity/tree/main/Test-MdiReadiness' })
    $items.Add(@{ Phase = 'Phase 1: Pre-Deployment'; Action = 'Set Power Option to High Performance on all sensor servers'; Scope = 'All sensor servers'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/prerequisites-sensor-version-2#sensor-requirements-and-recommendations'; CmdLine = 'Set-MDIConfiguration -Mode Domain -Configuration ProcessorPerformance -WhatIf'; CmdLineRefUrl = 'https://learn.microsoft.com/en-us/powershell/module/defenderforidentity/set-mdiconfiguration?view=defenderforidentity-latest' })
    $items.Add(@{ Phase = 'Phase 1: Pre-Deployment'; Action = 'Verify VM memory is fully allocated — disable Dynamic Memory on Hyper-V / VMware (reserve all guest memory)'; Scope = 'All sensor servers (VM)'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/prerequisites-sensor-version-2#dynamic-memory-requirements' })
    $items.Add(@{ Phase = 'Phase 1: Pre-Deployment'; Action = 'Verify time synchronization within 5 minutes across all sensor servers'; Scope = 'All sensor servers'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/prerequisites-sensor-version-2#sensor-requirements-and-recommendations' })

    # Phase 2: Connectivity
    $items.Add(@{ Phase = 'Phase 2: Connectivity'; Action = 'Allow outbound TCP 443 to <workspace-name>sensorapi.atp.azure.com from all sensor servers (no SSL inspection). The workspace name is derived from your Entra tenant name — find it in the Defender portal: Settings > System > About > Workspace Name.'; Scope = 'All sensor servers'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/prerequisites-sensor-version-2#required-ports' })
    $items.Add(@{ Phase = 'Phase 2: Connectivity'; Action = 'Allow outbound TCP/UDP 53 (DNS) from all sensor servers'; Scope = 'All sensor servers'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/prerequisites-sensor-version-2#required-ports' })
    if ($hasV2DC) {
        $items.Add(@{ Phase = 'Phase 2: Connectivity'; Action = 'Allow NNR ports outbound from v2.x DC sensors to all network devices: TCP 135 (NTLM/RPC), UDP 137 (NetBIOS), TCP 3389 (RDP)'; Scope = 'v2.x DC sensors'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/prerequisites-sensor-version-2#required-ports' })
    }

    if ($isMultiForest) {
        $items.Add(@{ Phase = 'Phase 2: Connectivity'; Action = 'Allow multi-forest ports outbound: TCP/UDP 389 (LDAP), TCP 636 (LDAPS), TCP 3268 (LDAP GC), TCP 3269 (LDAPS GC)'; Scope = 'All sensor servers'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/multi-forest' })
    }
    if ($hasProxy) {
        $items.Add(@{ Phase = 'Phase 2: Connectivity'; Action = "Configure forward proxy on sensor servers — allow traffic to MDI sensor API URL; ensure SSL inspection is excluded for MDI URLs"; Scope = 'All sensor servers'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-proxy' })
        if ($Answers.Connectivity['SSLInspection']) {
            $items.Add(@{ Phase = 'Phase 2: Connectivity'; Action = '⚠ BLOCKER: Exclude MDI sensor API URL from SSL/TLS inspection on the proxy — certificate-based mutual authentication will fail otherwise'; Scope = 'Proxy / Firewall'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-proxy' })
        }
    }
    if ($hasExpressRoute) {
        $items.Add(@{ Phase = 'Phase 2: Connectivity'; Action = 'Configure ExpressRoute Microsoft peering — add BGP community 12076:5220 (MDI) to your route filter'; Scope = 'Network / ExpressRoute'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/prerequisites-sensor-version-2#connectivity-requirements' })
    }
    if ($hasFirewallIP) {
        $items.Add(@{ Phase = 'Phase 2: Connectivity'; Action = 'Download Azure IP Ranges and configure the AzureAdvancedThreatProtection service tag in firewall rules'; Scope = 'Firewall'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/prerequisites-sensor-version-2#connectivity-requirements' })
        $items.Add(@{ Phase = 'Phase 2: Connectivity'; Action = 'Establish a recurring process to review Azure IP assignments for the AzureAdvancedThreatProtection service tag'; Scope = 'Firewall / Operations'; RefUrl = '' })
    }
    $items.Add(@{ Phase = 'Phase 2: Connectivity'; Action = 'Test connectivity from each sensor server to MDI cloud service using Test-MDISensorApiConnection or browser ping to <workspace>sensorapi.atp.azure.com/tri/sensor/api/ping'; Scope = 'All sensor servers'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/test-connectivity' })

    # Phase 3: Identity & DSA
    if ($allV3) {
        # v3.x sensors use LocalSystem — DSA is not supported and must NOT be configured
        $items.Add(@{ Phase = 'Phase 3: Identity & DSA'; Action = '✅ Not required — v3.x sensors authenticate to Active Directory using the LocalSystem identity. DSA and gMSA are not supported for v3.x and must NOT be configured. If migrating from sensor v2.x with a gMSA action account, remove it now: Settings > Identities > Directory service accounts > delete the gMSA entry. Leaving a gMSA enabled disables attack disruption and all response actions.'; Scope = 'v3.x sensors'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/deploy-sensor-v3#service-account-requirements' })
    } else {
    $items.Add(@{ Phase = 'Phase 3: Identity & DSA'; Action = 'Open Microsoft Defender portal (security.microsoft.com) — first sign-in with Security Administrator role creates the MDI workspace automatically'; Scope = 'Tenant'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/deploy-defender-identity' })

    if ($useGMSA) {
        if (-not $Answers.DSA['KdsRootKeyExists']) {
            $items.Add(@{ Phase = 'Phase 3: Identity & DSA'; Action = 'Run Add-KdsRootKey -EffectiveImmediately on a DC with Domain Admin permissions (once per forest — required as no gMSA accounts exist yet)'; Scope = 'Active Directory'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/create-directory-service-account-gmsa' })
        }
        $items.Add(@{ Phase = 'Phase 3: Identity & DSA'; Action = 'Create gMSA account and associated security group using the New-ADServiceAccount PowerShell script from the documentation'; Scope = 'Active Directory'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/create-directory-service-account-gmsa' })
        $items.Add(@{ Phase = 'Phase 3: Identity & DSA'; Action = 'Add all sensor server computer accounts to the gMSA security group'; Scope = 'Active Directory'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/create-directory-service-account-gmsa' })
        $items.Add(@{ Phase = 'Phase 3: Identity & DSA'; Action = 'Purge Kerberos tickets on sensor servers after group membership change: klist purge -li 0x3e7'; Scope = 'All sensor servers'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/create-directory-service-account-gmsa' })
        if ($hasV2) {
            $items.Add(@{ Phase = 'Phase 3: Identity & DSA'; Action = 'Verify gMSA has "Log on as a service" right on all v2.x sensor servers — the v2 sensor service runs as LocalService and impersonates the gMSA DSA; grant the right via Local Security Policy (secpol.msc) or GPO if the right is restricted'; Scope = 'v2.x sensor servers'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/create-directory-service-account-gmsa#verify-that-the-gmsa-account-has-the-required-rights' })
        }
    } else {
        $items.Add(@{ Phase = 'Phase 3: Identity & DSA'; Action = 'Create a dedicated read-only AD user account to use as the Directory Service Account (DSA)'; Scope = 'Active Directory'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/directory-service-accounts' })
    }

    $items.Add(@{ Phase = 'Phase 3: Identity & DSA'; Action = 'Grant DSA read access to the Deleted Objects container using the PowerShell script provided in the docs (sets List Contents + Read Property via dsacls.exe)'; Scope = 'Active Directory'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/create-directory-service-account-gmsa#grant-required-directory-service-account-permissions' })
    $items.Add(@{ Phase = 'Phase 3: Identity & DSA'; Action = 'Register DSA credentials in Microsoft Defender XDR: Settings > Identities > Directory service accounts > Add credentials'; Scope = 'Defender XDR Portal'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/create-directory-service-account-gmsa#configure-a-directory-service-account-in-microsoft-defender-xdr' })

    if ($isMultiForest) {
        $items.Add(@{ Phase = 'Phase 3: Identity & DSA'; Action = "Register $($DSAReqs['Count'] - 1) additional DSA credential(s) for non-Kerberos or untrusted forest(s) in Defender XDR portal"; Scope = 'Defender XDR Portal'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/multi-forest' })
    }
    if ($hasADFS) {
        $items.Add(@{ Phase = 'Phase 3: Identity & DSA'; Action = 'Grant DSA db_datareader permission on the AD FS AdfsConfiguration database on all AD FS servers (T-SQL or PowerShell)'; Scope = 'AD FS Servers'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/active-directory-federation-services#configure-read-permissions-for-the-ad-fs-database' })
    }
    if ($hasEC) {
        $items.Add(@{ Phase = 'Phase 3: Identity & DSA'; Action = 'Grant sensor computer account SELECT + EXECUTE permissions on ADSync database (required only if external SQL instance is used for Entra Connect)'; Scope = 'Entra Connect Servers'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/active-directory-federation-services#configure-permissions-for-the-microsoft-entra-connect-adsync-database' })
    }
    } # end if (-not $allV3)

    # Phase 4: Windows Event Auditing
    $items.Add(@{ Phase = 'Phase 4: Windows Event Auditing'; Action = 'Run a configuration report to review current audit policy gaps before making any changes'; Scope = 'Management workstation'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-windows-event-collection#before-you-begin'; CmdLine = "New-MDIConfigurationReport -Path 'C:\MDIReports' -Mode Domain -OpenHtmlReport"; CmdLineRefUrl = 'https://learn.microsoft.com/en-us/powershell/module/defenderforidentity/new-mdiconfigurationreport?view=defenderforidentity-latest' })

    if ($AuditApproach.PS) {
        $items.Add(@{ Phase = 'Phase 4: Windows Event Auditing'; Action = 'Apply Advanced Directory Services Audit Policy on DCs (events 4726, 4728–4733, 4741–4743, 4753–4758, 4776, 5136, 7045)'; Scope = 'Domain Controllers (GPO)'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-windows-event-collection#configure-directory-services-advanced-auditing'; CmdLine = 'Set-MDIConfiguration -Mode Domain -Configuration AdvancedAuditPolicyDCs -WhatIf'; CmdLineRefUrl = 'https://learn.microsoft.com/en-us/powershell/module/defenderforidentity/set-mdiconfiguration?view=defenderforidentity-latest' })
        $items.Add(@{ Phase = 'Phase 4: Windows Event Auditing'; Action = 'Configure NTLM auditing on DCs (event 8004)'; Scope = 'Domain Controllers (GPO)'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-windows-event-collection#configure-ntlm-auditing'; CmdLine = 'Set-MDIConfiguration -Mode Domain -Configuration NTLMAuditing -WhatIf'; CmdLineRefUrl = 'https://learn.microsoft.com/en-us/powershell/module/defenderforidentity/set-mdiconfiguration?view=defenderforidentity-latest' })
        $items.Add(@{ Phase = 'Phase 4: Windows Event Auditing'; Action = 'Configure auditing SACL on the domain root object (event 4662)'; Scope = 'Active Directory'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-windows-event-collection#configure-domain-object-auditing'; CmdLine = 'Set-MDIConfiguration -Mode Domain -Configuration DomainObjectAuditing -WhatIf'; CmdLineRefUrl = 'https://learn.microsoft.com/en-us/powershell/module/defenderforidentity/set-mdiconfiguration?view=defenderforidentity-latest'; AltAction = 'Configure via Active Directory Users and Computers (see docs)'; AltRefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-windows-event-collection#configure-domain-object-auditing' })
        $items.Add(@{ Phase = 'Phase 4: Windows Event Auditing'; Action = 'Enable AD Recycle Bin for full object deletion tracking'; Scope = 'Active Directory'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-windows-event-collection#configure-windows-event-collection-using-powershell'; CmdLine = 'Set-MDIConfiguration -Mode Domain -Configuration AdRecycleBin -WhatIf'; CmdLineRefUrl = 'https://learn.microsoft.com/en-us/powershell/module/defenderforidentity/set-mdiconfiguration?view=defenderforidentity-latest' })
        $items.Add(@{ Phase = 'Phase 4: Windows Event Auditing'; Action = 'Configure auditing on the AD Configuration Container (required for Exchange environments)'; Scope = 'Active Directory'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-windows-event-collection#configure-auditing-on-the-configuration-container'; CmdLine = 'Set-MDIConfiguration -Mode Domain -Configuration ConfigurationContainerAuditing -WhatIf'; CmdLineRefUrl = 'https://learn.microsoft.com/en-us/powershell/module/defenderforidentity/set-mdiconfiguration?view=defenderforidentity-latest'; AltAction = 'Configure via ADSI Edit (see docs)'; AltRefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-windows-event-collection#configure-auditing-on-the-configuration-container' })
    } else {
        $items.Add(@{ Phase = 'Phase 4: Windows Event Auditing'; Action = 'Enable Automatic Windows auditing: Defender portal > Settings > Identities > Advanced features > Automatic Windows auditing configuration'; Scope = 'Defender XDR Portal'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-windows-event-collection#configure-defender-for-identity-to-collect-windows-events-automatically-preview' })
    }

    if ($hasADFS) {
        $items.Add(@{ Phase = 'Phase 4: Windows Event Auditing'; Action = 'Configure AD FS object-level auditing SACL on the AD FS configuration container in AD'; Scope = 'Active Directory'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-windows-event-collection#configure-object-level-auditing-on-the-ad-fs-configuration-folder'; CmdLine = 'Set-MDIConfiguration -Mode Domain -Configuration AdfsAuditing -WhatIf'; CmdLineRefUrl = 'https://learn.microsoft.com/en-us/powershell/module/defenderforidentity/set-mdiconfiguration?view=defenderforidentity-latest'; AltAction = 'Configure via ADSI Edit (see docs)'; AltRefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-windows-event-collection#configure-object-level-auditing-on-the-ad-fs-configuration-folder' })
        $items.Add(@{ Phase = 'Phase 4: Windows Event Auditing'; Action = 'Configure AD FS audit Group Policy via GPO: Computer Config > Policies > Windows Settings > Security Settings > Advanced Audit Policy > Object Access > Audit Application Generated: Success and Failure'; Scope = 'AD FS Servers (GPO)'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-windows-event-collection#configure-a-group-policy-for-event-auditing' })
        $items.Add(@{ Phase = 'Phase 4: Windows Event Auditing'; Action = 'Enable verbose auditing on all AD FS servers'; Scope = 'AD FS Servers'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-windows-event-collection#configure-verbose-logging-for-ad-fs-events'; CmdLine = 'Set-AdfsProperties -AuditLevel Verbose'; CmdLineRefUrl = 'https://learn.microsoft.com/en-us/powershell/module/adfs/set-adfsproperties' })
    }
    if ($hasADCS) {
        $items.Add(@{ Phase = 'Phase 4: Windows Event Auditing'; Action = 'Configure CA-level audit policy on AD CS servers, then restart the Certificate Services service'; Scope = 'AD CS Servers'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-windows-event-collection#configure-auditing-on-an-ad-cs-server'; CmdLine = 'certutil -setreg CA\AuditFilter 127; Restart-Service certsvc'; CmdLineRefUrl = 'https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil#-setreg' })
        $items.Add(@{ Phase = 'Phase 4: Windows Event Auditing'; Action = 'Apply Advanced Audit Policy on CA servers via GPO (Object Access > Audit Certification Services: Success and Failure) — use -SkipGpoLink so the GPO is created unlinked, then manually link it to the OU containing your Issuing CA servers only'; Scope = 'AD CS Servers (GPO)'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-windows-event-collection#configure-auditing-on-an-ad-cs-server'; CmdLine = 'Set-MDIConfiguration -Mode Domain -Configuration AdvancedAuditPolicyCAs -SkipGpoLink -WhatIf'; CmdLineRefUrl = 'https://learn.microsoft.com/en-us/powershell/module/defenderforidentity/set-mdiconfiguration?view=defenderforidentity-latest' })
    }
    if ($hasEC) {
        $items.Add(@{ Phase = 'Phase 4: Windows Event Auditing'; Action = 'Configure Entra Connect server audit policy via GPO (Audit Logon/Logoff > Audit Logon: Success and Failure) — use -SkipGpoLink so the GPO is created unlinked, then manually link it to the OU containing your Entra Connect servers only'; Scope = 'Entra Connect Servers (GPO)'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-windows-event-collection#configure-auditing-on-microsoft-entra-connect'; CmdLine = 'Set-MDIConfiguration -Mode Domain -Configuration EntraConnectAuditing -SkipGpoLink -WhatIf'; CmdLineRefUrl = 'https://learn.microsoft.com/en-us/powershell/module/defenderforidentity/set-mdiconfiguration?view=defenderforidentity-latest'; AltAction = 'Configure via Group Policy Management (see docs)'; AltRefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-windows-event-collection#configure-auditing-on-microsoft-entra-connect' })
    }

    # Phase 5: Sensor Deployment
    if ($hasV3) {
        $items.Add(@{ Phase = 'Phase 5: Sensor Deployment'; Action = 'Activate MDI sensor v3.x: Defender portal > Settings > Identities > Activation > select eligible DCs > Activate'; Scope = 'v3.x DCs'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/activate-sensor' })
        $items.Add(@{ Phase = 'Phase 5: Sensor Deployment'; Action = 'Wait up to 1 hour for the first v3.x sensor to show status Running in Defender portal (subsequent sensors appear within 5 minutes)'; Scope = 'Defender XDR Portal'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/activate-sensor#confirm-sensor-activation' })
    }
    if ($hasV2) {
        $items.Add(@{ Phase = 'Phase 5: Sensor Deployment'; Action = 'Download MDI sensor v2.x package and copy access key: Defender portal > Settings > Identities > Sensors > Add sensor > Continue with classic sensor'; Scope = 'Management workstation'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/download-sensor' })
        if ($hasV2DC) {
            $items.Add(@{ Phase = 'Phase 5: Sensor Deployment'; Action = 'Install MDI sensor v2.x on all v2.x DCs — run Azure ATP sensor Setup.exe as Administrator or use silent install'; Scope = 'v2.x DCs'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/install-sensor' })
        }
        if ($hasProxy) {
            $items.Add(@{ Phase = 'Phase 5: Sensor Deployment'; Action = 'Configure proxy during sensor installation or post-install using Set-MDISensorProxyConfiguration or Deployer.exe'; Scope = 'v2.x sensor servers'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-proxy' })
        }
    }
    if ($hasADFS) {
        $items.Add(@{ Phase = 'Phase 5: Sensor Deployment'; Action = 'Install MDI sensor on all standalone AD FS federation servers (NOT required on WAP servers)'; Scope = 'Standalone AD FS Servers'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/active-directory-federation-services' })
        $items.Add(@{ Phase = 'Phase 5: Sensor Deployment'; Action = 'Configure resolver DC FQDN for AD FS sensors: Defender portal > Settings > Identities > Sensors > select sensor > Manage sensor'; Scope = 'Defender XDR Portal'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/active-directory-federation-services#post-installation-steps-optional' })
    }
    if ($hasADCS) {
        $items.Add(@{ Phase = 'Phase 5: Sensor Deployment'; Action = 'Install MDI sensor on all AD CS servers with the Certification Authority Role Service (not required on offline AD CS servers)'; Scope = 'Standalone AD CS Servers'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/active-directory-federation-services' })
    }
    if ($hasEC) {
        $hasECStaging = $Answers.StandaloneServers['EntraConnectStaging']['Count'] -gt 0
        $ecScope      = if ($hasECStaging) { 'Entra Connect Servers (Active + Staging)' } else { 'Entra Connect Server (Active)' }
        $ecAction     = if ($hasECStaging) { 'Install MDI sensor on BOTH active AND staging Entra Connect servers' } else { 'Install MDI sensor on the active Entra Connect server' }
        $items.Add(@{ Phase = 'Phase 5: Sensor Deployment'; Action = $ecAction; Scope = $ecScope; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/active-directory-federation-services' })
        $items.Add(@{ Phase = 'Phase 5: Sensor Deployment'; Action = 'Configure resolver DC FQDN for Entra Connect sensors: Defender portal > Settings > Identities > Sensors > select sensor > Manage sensor'; Scope = 'Defender XDR Portal'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/active-directory-federation-services#post-installation-steps-optional' })
    }
    $items.Add(@{ Phase = 'Phase 5: Sensor Deployment'; Action = 'Review and configure sensor settings in Defender portal: verify network adapters and description for each sensor'; Scope = 'Defender XDR Portal'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-sensor-settings' })

    # Phase 6: Validation
    $items.Add(@{ Phase = 'Phase 6: Validation'; Action = 'Confirm all sensors show status Running in Defender portal: Settings > Identities > Sensors'; Scope = 'Defender XDR Portal'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-sensor-settings#validate-successful-deployment' })
    if ($hasV3) {
        $items.Add(@{ Phase = 'Phase 6: Validation'; Action = 'Configure Unified Sensor RPC Auditing for v3.x DCs: Defender portal > Settings > Microsoft Defender XDR > Asset Rule Management > Create rule > apply tag “Unified Sensor RPC Audit” targeting v3.x DCs. Unlocks additional identity detections. Allow up to 1 hour for the rule to take effect.'; Scope = 'v3.x DCs'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/prerequisites-sensor-version-3#configure-rpc-auditing' })
    }
    $items.Add(@{ Phase = 'Phase 6: Validation'; Action = 'Run DNS connectivity test from a member device: nslookup > server <DC-FQDN> > ls -d <domain>'; Scope = 'Member device'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-sensor-settings#verify-security-alert-functionality' })
    $items.Add(@{ Phase = 'Phase 6: Validation'; Action = 'Verify MdiDnsQuery events appear in the device timeline in Defender portal (allow 15 minutes after first sensor activation)'; Scope = 'Defender XDR Portal'; RefUrl = '' })
    $items.Add(@{ Phase = 'Phase 6: Validation'; Action = 'Review health alerts in Defender portal: Settings > Identities > Health issues — resolve any configuration warnings'; Scope = 'Defender XDR Portal'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/health-alerts' })

    if ($hasADFS) {
        $items.Add(@{ Phase = 'Phase 6: Validation'; Action = 'Validate AD FS detection: Advanced Hunting > IdentityLogonEvents | where Protocol contains "Adfs"'; Scope = 'Defender XDR Portal'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/active-directory-federation-services#validate-successful-deployment' })
    }
    if ($hasADCS) {
        $items.Add(@{ Phase = 'Phase 6: Validation'; Action = 'Validate AD CS detection: Advanced Hunting > IdentityDirectoryEvents | where Protocol == "Adcs"'; Scope = 'Defender XDR Portal'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/deploy/active-directory-federation-services#validate-successful-deployment' })
    }

    # Phase 7: Identity & PAM Integrations (conditional on Section 10 answers)
    $integrations = $Answers.Integrations
    if ($integrations -and ($integrations['Okta'] -or $integrations['CyberArkId'] -or $integrations['SailPoint'] -or $integrations['PamEnabled'])) {

        if ($integrations['Okta']) {
            $items.Add(@{ Phase = 'Phase 7: Identity & PAM Integrations'; Action = 'Connect Okta to MDI — Step 1: In Okta, create a dedicated Okta account for MDI. Assign Super Admin role, verify account, sign in as that account to create an API token (Security > API > Tokens > Create Token > select "Any IP"). Store the token securely.'; Scope = 'Okta Admin Console'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/okta-integration#create-a-dedicated-okta-account' })
            $items.Add(@{ Phase = 'Phase 7: Identity & PAM Integrations'; Action = 'Connect Okta to MDI — Step 2: In Okta, add three custom string attributes to the User profile (Directory > Profile Editor > User > Add Attributes): ObjectSid, ObjectGuid, DistinguishedName (all Read Only). These are required for AD identity correlation.'; Scope = 'Okta Admin Console'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/okta-integration#add-custom-user-attributes' })
            $items.Add(@{ Phase = 'Phase 7: Identity & PAM Integrations'; Action = 'Connect Okta to MDI — Step 3: In Okta, create a custom role named "Microsoft Defender for Identity" (Security > Administrator > Roles > Create new role) with permissions: Edit user lifecycle states, Edit user authenticator operations, View roles/resources/admin assignments. Create a resource set with All users + All IAM resources. Assign both Read-Only Administrator and this custom role to the dedicated account. Remove Super Admin.'; Scope = 'Okta Admin Console'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/okta-integration#create-a-custom-okta-role' })
            $items.Add(@{ Phase = 'Phase 7: Identity & PAM Integrations'; Action = 'Connect Okta to MDI — Step 4: In Microsoft Defender portal, go to System > Data Management > Data Connectors > Catalog > Okta Single Sign-On > Connect a connector. Enter connector name, Okta domain (e.g. my.project.okta.com), and the API token. Select product: Microsoft Defender for Identity. Review and Connect. Allow up to 15 minutes for the connection to activate.'; Scope = 'Microsoft Defender Portal'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/okta-integration#connect-okta-to-microsoft-defender-for-identity' })
            if ($integrations['OktaAlreadyMDA']) {
                $items.Add(@{ Phase = 'Phase 7: Identity & PAM Integrations'; Action = '⚠ Okta duplicate data warning: Okta is already connected to Microsoft Defender for Cloud Apps (MDA). After connecting MDI, duplicate Okta user activity data will appear in the Defender portal. Review both connectors and determine if the MDA Okta connector should be removed to avoid duplicate events.'; Scope = 'Microsoft Defender Portal'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/okta-integration' })
            }
        }

        if ($integrations['CyberArkId']) {
            $items.Add(@{ Phase = 'Phase 7: Identity & PAM Integrations'; Action = 'Connect CyberArk Identity to MDI — Step 1 (Preview): In CyberArk Identity console, create a custom role (Identity Administration > Core Services > Roles > Add Role). Add User Management administrative rights. Create an OAuth Confidential Client user (Users > Add User > check "Is OAuth confidential client") and add it to the custom role + Privileged Cloud Auditors role.'; Scope = 'CyberArk Identity Console'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/connect-cyber-ark#create-a-custom-cyberark-identity-role' })
            $items.Add(@{ Phase = 'Phase 7: Identity & PAM Integrations'; Action = 'Connect CyberArk Identity to MDI — Step 2: In Defender portal, go to System > Data Management > Data Connectors > Catalog > CyberArk Identity > Connect a connector. Enter connector name, CyberArk Identity endpoint URL (<IdentityID>.id.cyberark.cloud), Privilege Cloud endpoint (<tenant>.privilegecloud.cyberark.cloud), and OAuth user credentials. Select Protection Types: Identity. Review and Connect.'; Scope = 'Microsoft Defender Portal'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/connect-cyber-ark#connect-cyberark-identity-to-defender-for-identity' })
            $items.Add(@{ Phase = 'Phase 7: Identity & PAM Integrations'; Action = 'Connect CyberArk Identity to MDI — Step 3 (for remediation actions): Create a Microsoft Sentinel integration profile for CyberArk (Settings > Microsoft Sentinel > Configuration > Automation > Integration profile) using the same OAuth credentials. This unlocks "Reset password for PAM account in CyberArk" and enable/disable user from the Defender portal.'; Scope = 'Microsoft Defender Portal'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/connect-cyber-ark#connect-cyberark-identity-to-defender-for-identity' })
        }

        if ($integrations['SailPoint']) {
            $items.Add(@{ Phase = 'Phase 7: Identity & PAM Integrations'; Action = 'Connect SailPoint ISC to MDI — Step 1 (Preview): In SailPoint Identity Security Cloud, create a dedicated user for this integration. Go to User Preferences > Personal Access Tokens > New Token. Add scopes: idn:accounts:read, idn:entitlement:read, sp:search:read, idn:accounts-state:manage. Copy the Client ID and Secret.'; Scope = 'SailPoint Identity Security Cloud'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/connect-sail-point#create-a-sailpoint-identity-security-cloud-personal-access-token' })
            $items.Add(@{ Phase = 'Phase 7: Identity & PAM Integrations'; Action = 'Connect SailPoint ISC to MDI — Step 2: In Defender portal, go to System > Data Management > Data Connectors > Catalog > SailPoint Identity Security Cloud > Connect a connector. Enter connector name, API Endpoint URL (contoso.api.identitynow.com — include "api" in URL), Client ID and Secret. Select Protection Types: Identity. Review and Connect. Verify Connection Status: Ok in My Connectors table.'; Scope = 'Microsoft Defender Portal'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/connect-sail-point#connect-sailpoint-identity-security-cloud-to-defender-for-identity' })
        }

        if ($integrations['PamEnabled']) {
            $vendor = $integrations['PamVendor']
            $pamRefUrl = switch -Wildcard ($vendor) {
                '*CyberArk*'    { 'https://community.cyberark.com/marketplace/s/#a35Ht0000018sDVIAY-a39Ht000004GLaEIAW' }
                '*BeyondTrust*' { 'https://docs.beyondtrust.com/insights/docs/microsoft-defender' }
                '*Delinea*'     { 'https://docs.delinea.com/online-help/integrations/microsoft/mdi/integrating-mdi.htm' }
                default         { 'https://learn.microsoft.com/en-us/defender-for-identity/integrate-microsoft-and-pam-services' }
            }
            $items.Add(@{ Phase = 'Phase 7: Identity & PAM Integrations'; Action = "Integrate $vendor with MDI: The integration is configured on the PAM vendor side. Once connected, MDI automatically tags PAM-managed identities in Defender XDR (visible in Assets > Identities). This enables direct password reset from the Defender portal (Assets > Identities > select identity > ⋯ > Reset password via $($vendor -replace ' .*$','')). Follow the vendor-specific integration guide linked in the reference."; Scope = $vendor; RefUrl = $pamRefUrl })
            $items.Add(@{ Phase = 'Phase 7: Identity & PAM Integrations'; Action = "Verify PAM identity tagging after $vendor integration: In Defender portal, go to Assets > Identities. Filter by identities that are PAM-managed and confirm the PAM tag appears. This confirms the integration is active and MDI is receiving privileged account context."; Scope = 'Microsoft Defender Portal'; RefUrl = 'https://learn.microsoft.com/en-us/defender-for-identity/integrate-microsoft-and-pam-services#reset-password' })
        }
    }

    return $items
}

#endregion

#region ─── JSON Export ──────────────────────────────────────────────────────

function Export-PlanJson {
    param ($Answers, $ServerGroups, $DSAReqs, $AuditApproach, $Checklist, $Warnings, [string] $OutputPath)

    $timestamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $safeName  = Get-SafeName -Name $Answers.CustomerName
    $filePath  = Join-Path $OutputPath "MDIDeploymentPlan-${safeName}-$timestamp.json"

    $plan = @{
        Meta = @{
            GeneratedAt   = $Answers.GeneratedAt
            CustomerName  = $Answers.CustomerName
            GeneratedBy   = 'Invoke-MDIDeploymentPlanner.ps1'
            SchemaVersion = '1.0'
        }
        Answers             = $Answers
        ServerGroups        = @($ServerGroups)
        DSARequirements     = $DSAReqs
        AuditingApproach    = $AuditApproach
        DeploymentChecklist = @($Checklist)
        WarningsAndBlockers = @($Warnings)
    }

    $plan | ConvertTo-Json -Depth 10 | Set-Content -Path $filePath -Encoding utf8
    # Remove draft now that the final plan is saved
    $draftPath = Join-Path $OutputPath "MDIDeploymentPlan-$(Get-SafeName -Name $Answers.CustomerName)-DRAFT.json"
    if (Test-Path $draftPath) { Remove-Item -Path $draftPath -Force }
    return $filePath
}

#endregion

#region ─── HTML Report ──────────────────────────────────────────────────────

function New-HtmlReport {
    param ($Answers, $ServerGroups, $DSAReqs, $AuditApproach, $Checklist, $Warnings, [string] $OutputPath)

    $timestamp   = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $safeName    = Get-SafeName -Name $Answers.CustomerName
    $filePath    = Join-Path $OutputPath "MDIDeploymentPlan-${safeName}-$timestamp.html"
    $reportDate  = (Get-Date).ToString('MMMM d, yyyy HH:mm')
    $customer    = ConvertTo-HtmlEncoded $Answers.CustomerName

    $totalSensors = 0; $v3Count = 0; $v2Count = 0
    foreach ($sg in $ServerGroups) {
        $n = [int]$sg['Count']
        $totalSensors += $n
        if ($sg['SensorVersion'] -eq 'v3.x') { $v3Count += $n }
        elseif ($sg['SensorVersion'] -eq 'v2.x') { $v2Count += $n }
    }
    $hasV2    = $v2Count -gt 0
    $blockers = @($Warnings | Where-Object { $_.Severity -eq 'BLOCKER' }).Count

    $licBadge = switch ($Answers.Licensing['Status']) {
        'Yes — license confirmed'       { '<span class="fl-pill fl-pill-success">Confirmed</span>' }
        'No — license not yet procured' { '<span class="fl-pill fl-pill-danger">Not Procured</span>' }
        default                         { '<span class="fl-pill fl-pill-warning">Unknown</span>' }
    }

    # ── Server table rows ──────────────────────────────────────────────────
    $serverRows = foreach ($g in $ServerGroups) {
        $verBadge = if ($g.SensorVersion -eq 'v3.x') {
            '<span class="fl-pill fl-pill-primary">v3.x</span>'
        } else {
            '<span class="fl-pill fl-pill-secondary">v2.x</span>'
        }
        $sizingStr = if ($g.SensorVersion -eq 'v3.x') {
            '<span style="color:var(--f-green);font-weight:600" title="v3 sensor self-limits resource usage">≤ 30% CPU &middot; ≤ 1.5 GB RAM</span>'
        } elseif ($g.SizingCPU -eq 'TBD') {
            '<span style="color:var(--f-amber);font-weight:600">Run Sizing Tool ↗</span>'
        } elseif ($g.SizingCPU -eq 'Minimal') {
            '<span style="color:var(--f-text2)">Minimal</span>'
        } else {
            "$($g.SizingCPU) cores / $($g.SizingRAM) GB RAM"
        }
        $notesHtml = if ($g.Notes) {
            "<small style='color:var(--f-text2)'>$(ConvertTo-HtmlEncoded $g.Notes)</small>"
        } else { '<span style="color:var(--f-text2)">—</span>' }

        "<tr>
          <td>$(ConvertTo-HtmlEncoded $g.OSVersion)</td>
          <td>$(ConvertTo-HtmlEncoded $g.RolesStr)</td>
          <td class='text-center'>$(if ($g.IsRODC) { '<span class="fl-pill fl-pill-warning">RODC</span>' } else { 'No' })</td>
          <td class='text-center'>$(ConvertTo-HtmlEncoded $g.Traffic)</td>
          <td class='text-center fw-bold'>$(ConvertTo-HtmlEncoded $g['Count'].ToString())</td>
          <td class='text-center'>$verBadge</td>
          <td>$sizingStr</td>
          <td>$notesHtml</td>
        </tr>"
    }

    # ── Warnings section ───────────────────────────────────────────────────
    $warningsHtml = if ($Warnings.Count -gt 0) {
        $warnItems = foreach ($w in $Warnings) {
            $cls = switch ($w.Severity) { 'BLOCKER' { 'danger' } 'WARNING' { 'warning' } default { 'info' } }
            $ico = switch ($w.Severity) { 'BLOCKER' { '🚫' }     'WARNING' { '⚠'      } default { 'ℹ️'  } }
            $ref = if ($w.RefUrl) { " <a href='$($w.RefUrl)' target='_blank'>Reference ↗</a>" } else { '' }
            "<div class='fl-alert fl-alert-$cls'>$ico <strong>[$($w.Severity)]</strong> $(ConvertTo-HtmlEncoded $w.Message)$ref</div>"
        }
        $warnItems -join "`n"
    } else {
        "<div class='fl-alert fl-alert-success'>✅ No blockers or warnings identified.</div>"
    }

    # ── Planned Identity & PAM Integrations section ────────────────────────
    $integ = $Answers.Integrations
    $integrationsHtml = if ($integ -and ($integ['Okta'] -or $integ['CyberArkId'] -or $integ['SailPoint'] -or $integ['PamEnabled'])) {
        $rows = [System.Collections.Generic.List[string]]::new()
        if ($integ['Okta']) {
            $dupNote = if ($integ['OktaAlreadyMDA']) { "<br><span style='color:var(--f-amber);font-size:12px'>⚠ Already connected to MDA — duplicate data risk. See Warnings section.</span>" } else { '' }
            $rows.Add("<tr><td><strong>Okta Single Sign-On</strong></td><td>Identity connector (user activity, sign-ins). Prerequisites: Okta Developer or Enterprise license; dedicated Super Admin account for token creation.$dupNote</td><td><a href='https://learn.microsoft.com/en-us/defender-for-identity/okta-integration' target='_blank'>Setup guide ↗</a></td></tr>")
        }
        if ($integ['CyberArkId']) {
            $rows.Add("<tr><td><strong>CyberArk Identity</strong> <span class='fl-pill fl-pill-primary' style='font-size:11px'>Preview</span></td><td>SaaS identity connector. Adds CyberArk users to identity inventory, enables posture recommendations, and unlocks PAM password reset from Defender portal. Prerequisites: System Admin role in CyberArk Identity to create an OAuth Confidential Client.</td><td><a href='https://learn.microsoft.com/en-us/defender-for-identity/connect-cyber-ark' target='_blank'>Setup guide ↗</a></td></tr>")
        }
        if ($integ['SailPoint']) {
            $rows.Add("<tr><td><strong>SailPoint Identity Security Cloud</strong> <span class='fl-pill fl-pill-primary' style='font-size:11px'>Preview</span></td><td>IGA connector. Adds SailPoint accounts/entitlements to identity inventory and enables governance posture recommendations. Prerequisites: SailPoint IdentityNow Admin to create Personal Access Token (scopes: idn:accounts:read, idn:entitlement:read, sp:search:read, idn:accounts-state:manage).</td><td><a href='https://learn.microsoft.com/en-us/defender-for-identity/connect-sail-point' target='_blank'>Setup guide ↗</a></td></tr>")
        }
        if ($integ['PamEnabled']) {
            $vendor = $integ['PamVendor']
            $pamRef = switch -Wildcard ($vendor) {
                '*CyberArk*'    { 'https://community.cyberark.com/marketplace/s/#a35Ht0000018sDVIAY-a39Ht000004GLaEIAW' }
                '*BeyondTrust*' { 'https://docs.beyondtrust.com/insights/docs/microsoft-defender' }
                '*Delinea*'     { 'https://docs.delinea.com/online-help/integrations/microsoft/mdi/integrating-mdi.htm' }
                default         { 'https://learn.microsoft.com/en-us/defender-for-identity/integrate-microsoft-and-pam-services' }
            }
            $rows.Add("<tr><td><strong>$(ConvertTo-HtmlEncoded $vendor)</strong> <span class='fl-pill fl-pill-secondary' style='font-size:11px'>PAM</span></td><td>Vendor-side integration — no Defender portal connector required. Once configured, MDI automatically tags PAM-managed identities in Defender XDR and enables direct password reset from the portal (Assets &gt; Identities).</td><td><a href='$pamRef' target='_blank'>Vendor guide ↗</a></td></tr>")
        }
        @"
<p style='font-size:13px;color:var(--f-text2);margin-bottom:10px'>These integrations are configured <strong>after</strong> MDI deployment. Step-by-step tasks are in the <strong>Phase 7</strong> checklist below.</p>
<div class='table-responsive'>
<table class='fl-table'>
  <thead><tr><th>Integration</th><th>Purpose &amp; Prerequisites</th><th>Guide</th></tr></thead>
  <tbody>$($rows -join "`n")</tbody>
</table>
</div>
"@
    } else {
        "<p style='color:var(--f-text2);font-size:13px'>No third-party identity or PAM integrations selected.</p>"
    }

    # ── Checklist phases ───────────────────────────────────────────────────
    $phaseGroups    = $Checklist | Group-Object -Property Phase
    $checklistHtml  = foreach ($phase in $phaseGroups) {
        $phaseItems = foreach ($item in $phase.Group) {
            $ref = if ($item.RefUrl) {
                "<a href='$($item.RefUrl)' target='_blank' style='margin-left:6px;font-size:12px;color:var(--f-text2)' title='Microsoft Learn'>📖</a>"
            } else { '' }
            $scopeBadge = if ($item.Scope) {
                "<span class='fl-pill fl-pill-secondary' style='margin-left:6px;font-size:11px'>$(ConvertTo-HtmlEncoded $item.Scope)</span>"
            } else { '' }
            $cmdLine = if ($item.ContainsKey('CmdLine') -and $item.CmdLine) {
                $cmdRef = if ($item.ContainsKey('CmdLineRefUrl') -and $item.CmdLineRefUrl) {
                    "<a href='$($item.CmdLineRefUrl)' target='_blank' style='margin-left:4px;font-size:12px;color:var(--f-text2)' title='Microsoft Learn'>📖</a>"
                } else { '' }
                "<div style='margin-top:4px'><code>$(ConvertTo-HtmlEncoded $item.CmdLine)</code>$cmdRef</div>"
            } else { '' }
            "<li class='fl-checklist-item'>
              <input type='checkbox' onchange='toggleDone(this)'>
              <div class='item-body'>
                $(ConvertTo-HtmlEncoded $item.Action)$scopeBadge$ref$cmdLine
              </div>
            </li>"
        }
        $phaseNote = if ($phase.Name -eq 'Phase 1: Pre-Deployment') {
            "<div class='fl-alert fl-alert-danger' style='margin-bottom:12px'><strong>🛑 Before running any PowerShell command in this phase:</strong> The cmdlets shown are pre-populated with <code>-WhatIf</code> to prevent unintended changes. <strong>Do not remove <code>-WhatIf</code> unless you have read the full cmdlet documentation, understand exactly what will be changed on the target system, and have obtained the necessary change-management approval.</strong> Some of these commands modify system configuration directly on all sensor servers in scope.</div>"
        } elseif ($phase.Name -eq 'Phase 4: Windows Event Auditing') {
            "<div class='fl-alert fl-alert-danger' style='margin-bottom:12px'><strong>🛑 Before running any PowerShell command in this phase:</strong> The <code>Set-MDIConfiguration</code> cmdlets shown are pre-populated with <code>-WhatIf</code>. When executed without <code>-WhatIf</code>, these cmdlets <strong>create and link Group Policy Objects in your Active Directory domain</strong>, which will immediately affect all domain controllers or servers in scope. <strong>Do not proceed without fully understanding the cmdlet behavior, reviewing the WhatIf output, and obtaining change-management approval.</strong> Always run the <code>-WhatIf</code> version first, review every line of output, then re-run without <code>-WhatIf</code> only when you are certain the changes are correct and approved.</div>"
        } else { '' }
        "<div style='margin-bottom:20px'>
          <h5>$(ConvertTo-HtmlEncoded $phase.Name)</h5>
          $phaseNote
          <ul class='fl-checklist'>
            $($phaseItems -join "`n")
          </ul>
        </div>"
    }

    # ── DSA section ────────────────────────────────────────────────────────
    $allV3Report = ($ServerGroups | Where-Object { $_['SensorVersion'] -ne 'v3.x' } | Measure-Object).Count -eq 0
    $dsaTypeLabel = if ($Answers.DSA['Type'] -like '*gMSA*') {
        'Group Managed Service Account (gMSA)'
    } else {
        'Regular AD User Account'
    }
    $kdsStep = if (-not $Answers.DSA['KdsRootKeyExists']) {
        "<li>Run <code>Add-KdsRootKey -EffectiveImmediately</code> on a DC (once per forest, requires Domain Admin) — <strong>no KDS Root Key present yet</strong></li>"
    } else {
        "<!-- KDS Root Key already present — step skipped -->"
    }
    $gmsaHtml = if ($Answers.DSA['Type'] -like '*gMSA*') { @"
        <div class="mt-3">
          <h6 class="fw-bold">gMSA Setup Steps</h6>
          <ol>
            $kdsStep
            <li>Create the gMSA account and security group using <code>New-ADServiceAccount</code> (see documentation script)</li>
            <li>Add all sensor server computer accounts to the gMSA security group</li>
            <li>Grant DSA read access to the Deleted Objects container using <code>dsacls.exe LCRP</code></li>
            $(if ($hasV2) { '<li>Verify the "Log on as a service" right on all v2.x sensor servers (<code>secpol.msc</code> or GPO) — only required for v2.x; the v2 sensor service impersonates the gMSA DSA</li>' })
            <li>Purge Kerberos tickets after group membership changes: <code>klist purge -li 0x3e7</code></li>
            <li>Register the gMSA in Defender XDR: Settings &gt; Identities &gt; Directory service accounts &gt; Add credentials</li>
          </ol>
          <a href="https://learn.microsoft.com/en-us/defender-for-identity/deploy/create-directory-service-account-gmsa" target="_blank">Full gMSA Setup Guide ↗</a>
        </div>
"@ } else { '' }

    # ── Connectivity section ───────────────────────────────────────────────
    $proxyHtml = if ($Answers.Connectivity['Method'] -eq 'Forward proxy') {
        $proxyUrl = $Answers.Connectivity['ProxyUrl']
        $proxyDisplay = if ($proxyUrl -eq 'TBD' -or -not $proxyUrl) {
            "<code style='color:var(--f-amber)'>TBD</code> <span style='font-size:12px;color:var(--f-text2)'>(provide before sensor deployment)</span>"
        } else {
            "<code>$(ConvertTo-HtmlEncoded $proxyUrl)</code>"
        }
        "<p><strong>Proxy URL:</strong> $proxyDisplay</p>
         <p><strong>Authentication required:</strong> $(if ($Answers.Connectivity['ProxyAuthRequired']) { 'Yes' } else { 'No' })</p>"
    } else { '' }

    $sslWarnHtml = if ($Answers.Connectivity['SSLInspection']) {
        "<div class='fl-alert fl-alert-danger' style='margin-top:10px'>🚫 <strong>BLOCKER:</strong> SSL/TLS inspection must be disabled for MDI URLs. MDI sensors use certificate-based mutual authentication — interception will break connectivity and prevent sensor registration.</div>"
    } else { '' }

    $expresRouteHtml = if ($Answers.Connectivity['Method'] -eq 'Azure ExpressRoute (Microsoft peering)') {
        "<div class='fl-alert fl-alert-info' style='margin-top:10px'>ℹ️ <strong>ExpressRoute:</strong> Add BGP community value <strong>12076:5220</strong> (Microsoft Defender for Identity) to your route filter via ExpressRoute Microsoft peering.</div>"
    } else { '' }

    # ── Auditing section ───────────────────────────────────────────────────
    $auditCommandHtml = if ($AuditApproach.PS) {
        @"
        <div class="mt-3">
          <h6 class="fw-bold">PowerShell Commands</h6>
          <pre><code>Install-Module DefenderForIdentity -Scope CurrentUser

# Review current configuration and gaps:
New-MDIConfigurationReport -Path 'C:\MDIReports' -Mode Domain -OpenHtmlReport

# Apply all required audit settings via Group Policy:
Set-MDIConfiguration -Mode Domain -Configuration All</code></pre>
        </div>
"@
    } else {
        "<p class='mt-2'><strong>Portal steps:</strong> Microsoft Defender portal &gt; Settings &gt; Identities &gt; Advanced features &gt; enable <strong>Automatic Windows auditing configuration</strong></p>"
    }

    # ── Full HTML ──────────────────────────────────────────────────────────
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>MDI Deployment Plan — $customer</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" crossorigin="anonymous">
  <style>
    /* ── Fluent UI colour tokens ─────────────────────────────────── */
    :root {
      --f-bg:         #faf9f8;
      --f-surface:    #ffffff;
      --f-border:     #e0e0e0;
      --f-border2:    #d1d1d1;
      --f-text:       #242424;
      --f-text2:      #616161;
      --f-blue:       #0078d4;
      --f-green:      #107c10;
      --f-green-bg:   #dff6dd;
      --f-red:        #b10e1c;
      --f-red-bg:     #fde7e9;
      --f-amber:      #7f3300;
      --f-amber-bg:   #fff8f0;
      --f-teal:       #006e6e;
      --f-teal-bg:    #e5f8f8;
      --f-neutral:    #424242;
      --f-neutral-bg: #f5f5f5;
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --f-bg:         #141414;
        --f-surface:    #1b1a19;
        --f-border:     #484644;
        --f-border2:    #3b3a39;
        --f-text:       #f3f2f1;
        --f-text2:      #d2d0ce;
        --f-green:      #6dd36d;
        --f-green-bg:   #0a3d0a;
        --f-red:        #f47474;
        --f-red-bg:     #420c0c;
        --f-amber:      #ffcc87;
        --f-amber-bg:   #3d1f00;
        --f-teal:       #6decec;
        --f-teal-bg:    #003333;
        --f-neutral:    #d2d0ce;
        --f-neutral-bg: #3b3a39;
      }
    }
    /* ── Base ────────────────────────────────────────────────────── */
    *, *::before, *::after { box-sizing: border-box; }
    body {
      font-family: 'Segoe UI', system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
      font-size: 14px;
      background: var(--f-bg);
      color: var(--f-text);
      margin: 0; padding: 0;
    }
    /* ── Page header ──────────────────────────────────────────────  */
    .page-header {
      position: sticky;
      top: 0;
      z-index: 100;
      background: var(--f-surface);
      border-bottom: 1px solid var(--f-border);
      padding: 16px 24px 14px;
    }
    .page-breadcrumb { font-size: 12px; color: var(--f-text2); margin-bottom: 6px; }
    .page-title { font-size: 20px; font-weight: 600; color: var(--f-text); margin: 0 0 6px; }
    .page-meta { font-size: 12px; color: var(--f-text2); display: flex; flex-wrap: wrap; gap: 4px 12px; }
    /* ── Content area ─────────────────────────────────────────────  */
    .content-area { padding: 20px 24px; max-width: 1200px; margin: 0 auto; }
    /* ── Stat cards ───────────────────────────────────────────────  */
    .stat-card { background: var(--f-surface); border: 1px solid var(--f-border); border-radius: 4px; padding: 16px; height: 100%; }
    .stat-label { font-size: 12px; color: var(--f-text2); margin-bottom: 4px; }
    .stat-value { font-size: 28px; font-weight: 600; line-height: 1.2; color: var(--f-text); }
    .v-green { color: var(--f-green) !important; }
    .v-red   { color: var(--f-red)   !important; }
    .v-blue  { color: var(--f-blue)  !important; }
    .v-amber { color: var(--f-amber) !important; }
    /* ── Section cards ────────────────────────────────────────────  */
    .section-card {
      background: var(--f-surface);
      border: 1px solid var(--f-border);
      border-radius: 4px;
      padding: 20px 24px;
      margin-bottom: 16px;
    }
    .section-card h4 {
      font-size: 16px; font-weight: 600; color: var(--f-text);
      border-bottom: 1px solid var(--f-border); padding-bottom: 10px; margin-bottom: 16px;
    }
    .section-card h5 {
      font-size: 14px; font-weight: 600; color: var(--f-blue);
      border-bottom: 1px solid var(--f-border); padding-bottom: 8px; margin-bottom: 12px;
    }
    .section-card h6 { font-size: 13px; font-weight: 600; margin-top: 14px; margin-bottom: 8px; }
    /* ── Status pills ─────────────────────────────────────────────  */
    .fl-pill {
      display: inline-flex; align-items: center; padding: 2px 10px;
      border-radius: 12px; font-size: 12px; white-space: nowrap;
    }
    .fl-pill-success   { background: var(--f-green-bg);   color: var(--f-green); }
    .fl-pill-danger    { background: var(--f-red-bg);     color: var(--f-red); }
    .fl-pill-primary   { background: #deecf9;             color: #005a9e; }
    .fl-pill-warning   { background: var(--f-amber-bg);   color: var(--f-amber); }
    .fl-pill-secondary { background: var(--f-neutral-bg); color: var(--f-neutral); }
    @media (prefers-color-scheme: dark) {
      .fl-pill-primary { background: #0a2a5a; color: #6ab7f5; }
    }
    /* ── Fluent alerts ────────────────────────────────────────────  */
    .fl-alert {
      padding: 10px 14px; border-radius: 4px; border-left: 3px solid;
      margin-bottom: 8px; font-size: 13px; line-height: 1.5;
    }
    .fl-alert-danger  { background: var(--f-red-bg);   border-color: var(--f-red);   color: var(--f-text); }
    .fl-alert-warning { background: var(--f-amber-bg); border-color: var(--f-amber); color: var(--f-text); }
    .fl-alert-info    { background: #deecf9;           border-color: var(--f-blue);  color: var(--f-text); }
    .fl-alert-success { background: var(--f-green-bg); border-color: var(--f-green); color: var(--f-text); }
    /* ── Table ────────────────────────────────────────────────────  */
    .fl-table { width: 100%; border-collapse: collapse; font-size: 13px; }
    .fl-table thead th {
      background: var(--f-bg); color: var(--f-text); font-weight: 600;
      border-bottom: 2px solid var(--f-border); padding: 10px 12px; text-align: left;
    }
    .fl-table tbody td {
      padding: 10px 12px; border-bottom: 1px solid var(--f-border);
      vertical-align: middle; background: var(--f-surface); color: var(--f-text);
    }
    .fl-table tbody tr:hover td { background: var(--f-bg); }
    .fl-table tbody tr:last-child td { border-bottom: none; }
    .fl-table thead th.text-center, .fl-table tbody td.text-center { text-align: center; }
    /* ── Checklist ────────────────────────────────────────────────  */
    .fl-checklist { list-style: none; padding: 0; margin: 0; }
    .fl-checklist-item {
      display: flex; align-items: flex-start; gap: 10px;
      padding: 10px 0; border-bottom: 1px solid var(--f-border); font-size: 13px;
    }
    .fl-checklist-item:last-child { border-bottom: none; }
    .fl-checklist-item input[type=checkbox] { margin-top: 2px; flex-shrink: 0; cursor: pointer; }
    .fl-checklist-item .item-body { flex: 1; }
    .fl-checklist-item .item-body.done { text-decoration: line-through; color: var(--f-text2); }
    /* ── Code ─────────────────────────────────────────────────────  */
    code {
      background: var(--f-neutral-bg); border: 1px solid var(--f-border);
      border-radius: 3px; padding: 1px 5px; font-size: 12px; color: var(--f-text);
    }
    pre {
      background: var(--f-neutral-bg); border: 1px solid var(--f-border);
      border-radius: 4px; padding: 12px 14px; font-size: 12px; overflow-x: auto; margin-top: 10px;
    }
    pre code { background: none; border: none; padding: 0; }
    /* ── Footer ───────────────────────────────────────────────────  */
    .page-footer { font-size: 12px; color: var(--f-text2); padding: 8px 0 20px; }
    /* ── Print ────────────────────────────────────────────────────  */
    @media print {
      * { -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important; }
      @page { size: A4; margin: 15mm; }
      body { background: white !important; color: #000 !important; font-size: 9pt !important; }
      .page-header { border-bottom: 2px solid #0078d4 !important; padding: 10px 0 8px !important; }
      .page-title { font-size: 14pt !important; }
      .page-meta  { font-size: 8pt !important; }
      .no-print { display: none !important; }
      .section-card { border: 1px solid #dee2e6 !important; padding: 8px 10px !important; margin-bottom: 8px !important; break-inside: avoid; }
      .section-card h4 { font-size: 10pt !important; }
      .fl-table { font-size: 7.5pt !important; }
      .fl-table th, .fl-table td { padding: 3px 5px !important; }
      .fl-alert { font-size: 7.5pt !important; padding: 4px 8px !important; break-inside: avoid; }
      pre { font-size: 7pt !important; padding: 6px !important; white-space: pre-wrap !important; break-inside: avoid; }
      .fl-checklist-item { font-size: 8pt !important; padding: 4px 0 !important; }
      a[href]::after { content: none !important; }
    }
  </style>
</head>
<body>

  <!-- Page header -->
  <div class="page-header">
    <div class="page-breadcrumb">Microsoft Defender for Identity &rsaquo; Deployment Planning</div>
    <h1 class="page-title">MDI Deployment Plan &mdash; $customer</h1>
    <div class="page-meta">
      <span>Generated: $reportDate</span>
    </div>
  </div>

  <div class="content-area">

    <!-- Summary Cards -->
    <div class="row g-3 mb-4">
      <div class="col-6 col-sm-4 col-lg-3">
        <div class="stat-card"><div class="stat-label">Total Sensors</div><div class="stat-value">$totalSensors</div></div>
      </div>
      <div class="col-6 col-sm-4 col-lg-3">
        <div class="stat-card"><div class="stat-label">Sensor v3.x</div><div class="stat-value v-blue">$v3Count</div></div>
      </div>
      <div class="col-6 col-sm-4 col-lg-3">
        <div class="stat-card"><div class="stat-label">Sensor v2.x</div><div class="stat-value" style="color:var(--f-text2)">$v2Count</div></div>
      </div>
      <div class="col-6 col-sm-4 col-lg-3">
        <div class="stat-card"><div class="stat-label">AD Forest(s)</div><div class="stat-value">$($Answers.Topology['ForestCount'])</div></div>
      </div>
      <div class="col-6 col-sm-4 col-lg-3">
        <div class="stat-card"><div class="stat-label">AD Domain(s)</div><div class="stat-value">$($Answers.Topology['DomainCount'])</div></div>
      </div>
      <div class="col-6 col-sm-4 col-lg-3">
        $(if ($allV3Report) {
          '<div class="stat-card"><div class="stat-label">DSA Credential(s)</div><div class="stat-value" style="color:var(--f-text2)">N/A</div></div>'
        } else {
          "<div class='stat-card'><div class='stat-label'>DSA Credential(s)</div><div class='stat-value'>$($DSAReqs['Count'])</div></div>"
        })
      </div>
      <div class="col-6 col-sm-4 col-lg-3">
        <div class="stat-card">
          <div class="stat-label">Blocker(s)</div>
          <div class="stat-value $(if ($blockers -gt 0) { 'v-red' } else { 'v-green' })">$blockers</div>
        </div>
      </div>
      <div class="col-6 col-sm-4 col-lg-3">
        <div class="stat-card"><div class="stat-label">License Status</div><div style="margin-top:6px">$licBadge</div></div>
      </div>
    </div>

    <!-- Warnings & Blockers -->
    <div class="section-card">
      <h4>Warnings &amp; Blockers</h4>
      $warningsHtml
    </div>

    <!-- Server Deployment Overview -->
    <div class="section-card">
      <h4>Server Deployment Overview</h4>
      <div class="table-responsive">
        <table class="fl-table">
          <thead>
            <tr>
              <th>OS Version</th><th>Roles</th><th class="text-center">RODC</th>
              <th class="text-center">Traffic (pkt/s)</th><th class="text-center">Count</th>
              <th class="text-center">Sensor</th><th>Sizing (per sensor)</th><th>Notes</th>
            </tr>
          </thead>
          <tbody>
            $($serverRows -join "`n")
          </tbody>
        </table>
      </div>
      <p style="font-size:12px;color:var(--f-text2);margin-top:10px;margin-bottom:0">
        Sizing = sensor-only resource consumption (not total DC capacity). CPU = non-hyperthreaded cores only.<br>
        v3.x sensors self-limit to ≤ 30% CPU and ≤ 1.5 GB RAM — traffic-based sizing does not apply.
        &nbsp;<a href="https://learn.microsoft.com/en-us/defender-for-identity/deploy/capacity-planning" target="_blank">Capacity Planning Guide ↗</a>
        &nbsp;|&nbsp;<a href="https://aka.ms/mdi/sizingtool" target="_blank">Download MDI Sizing Tool ↗</a>
      </p>
    </div>

    <!-- DSA Configuration -->
    <div class="section-card">
      <h4>Directory Service Account (DSA)</h4>
      $(if ($allV3Report) {
        '<div class="fl-alert fl-alert-success" style="margin-bottom:0"><strong>✅ Not required — v3.x sensors use LocalSystem</strong><br>The v3.x sensor authenticates to Active Directory using the <strong>LocalSystem</strong> identity of the server. DSA and gMSA are <strong>not supported</strong> for v3.x sensors and must NOT be configured.<br><br>⚠️ <strong>Migrating from v2.x?</strong> If a gMSA action account was previously configured, remove it: <em>Settings &gt; Identities &gt; Directory service accounts</em>. Leaving a gMSA enabled on a v3.x sensor disables attack disruption and all response actions.<br><br><a href="https://learn.microsoft.com/en-us/defender-for-identity/deploy/deploy-sensor-v3#service-account-requirements" target="_blank">Service account requirements for v3.x ↗</a></div>'
      } else {
        "<p><strong>Account type:</strong> $dsaTypeLabel</p><p><strong>Required DSA credentials:</strong> $($DSAReqs['Count'])</p><p><strong>Notes:</strong> $(ConvertTo-HtmlEncoded $DSAReqs.Notes)</p>$gmsaHtml"
      })
    </div>

    <!-- Connectivity -->
    <div class="section-card">
      <h4>Connectivity Configuration</h4>
      <p><strong>Method:</strong> $(ConvertTo-HtmlEncoded $Answers.Connectivity['Method'])</p>
      $proxyHtml
      $sslWarnHtml
      $expresRouteHtml
      <h6>Required URLs &amp; Ports</h6>
      <ul style="font-size:13px">
        <li><code>&lt;workspace-name&gt;sensorapi.atp.azure.com</code> &mdash; TCP 443 outbound (MDI cloud service)<br><small style="color:var(--f-text2)">The workspace name is derived from your Entra tenant name. Find it in the Defender portal: Settings &gt; System &gt; About &gt; Workspace Name.</small></li>
        <li><code>crl.microsoft.com</code>, <code>ctldl.windowsupdate.com</code>, <code>www.microsoft.com/pkiops/*</code> &mdash; certificate validation</li>
        <li><code>sensorpackage-prd.mdi.securitycenter.microsoft.com</code> &mdash; TCP 443 (sensor package download)</li>
      </ul>
      <p style="font-size:12px;color:var(--f-text2);margin-bottom:6px">SSL/TLS inspection is NOT supported. MDI uses certificate-based mutual authentication.</p>
      <a href="https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-proxy" target="_blank" style="font-size:13px">Proxy Configuration Guide ↗</a>
    </div>

    <!-- Windows Event Auditing -->
    <div class="section-card">
      <h4>Windows Event Auditing</h4>
      <p><strong>Recommended approach:</strong> $(ConvertTo-HtmlEncoded $AuditApproach.Approach)</p>
      <p>$(ConvertTo-HtmlEncoded $AuditApproach.Description)</p>
      $auditCommandHtml
      <h6 style="margin-top:16px">Required Event IDs</h6>
      <div class="table-responsive">
        <table class="fl-table">
          <thead><tr><th>Category</th><th>Subcategory</th><th>Event IDs</th></tr></thead>
          <tbody>
            <tr><td>Account Logon</td><td>Credential Validation</td><td>4776</td></tr>
            <tr><td>Account Management</td><td>Computer Account Management</td><td>4741, 4743</td></tr>
            <tr><td>Account Management</td><td>Security Group Management</td><td>4728&ndash;4758</td></tr>
            <tr><td>Account Management</td><td>User Account Management</td><td>4726</td></tr>
            <tr><td>DS Access</td><td>Directory Service Changes</td><td>5136</td></tr>
            <tr><td>DS Access</td><td>Directory Service Access</td><td>4662</td></tr>
            <tr><td>System</td><td>Security System Extension</td><td>7045</td></tr>
            <tr><td>NTLM (Group Policy)</td><td>Restrict NTLM</td><td>8004</td></tr>
          </tbody>
        </table>
      </div>
      <p style="margin-top:10px;margin-bottom:0"><a href="https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-windows-event-collection" target="_blank">Windows Event Auditing Guide ↗</a></p>
    </div>

    <!-- Planned Identity & PAM Integrations -->
    <div class="section-card">
      <h4>Planned Identity &amp; PAM Integrations</h4>
      $integrationsHtml
    </div>

    <!-- Deployment Checklist -->
    <div class="section-card">
      <h4>Deployment Checklist</h4>
      $($checklistHtml -join "`n")
    </div>

    <!-- References -->
    <div class="section-card">
      <h4>References</h4>
      <div class="row">
        <div class="col-md-6">
          <ul style="font-size:13px">
            <li><a href="https://learn.microsoft.com/en-us/defender-for-identity/what-is" target="_blank">What is Microsoft Defender for Identity?</a></li>
            <li><a href="https://learn.microsoft.com/en-us/defender-for-identity/deploy/deploy-defender-identity" target="_blank">Deployment Overview</a></li>
            <li><a href="https://learn.microsoft.com/en-us/defender-for-identity/deploy/prerequisites-sensor-version-2" target="_blank">Sensor v2.x Prerequisites</a></li>
            <li><a href="https://learn.microsoft.com/en-us/defender-for-identity/deploy/deploy-sensor-v3" target="_blank">Sensor v3.x Prerequisites</a></li>
            <li><a href="https://learn.microsoft.com/en-us/defender-for-identity/deploy/capacity-planning" target="_blank">Capacity Planning</a></li>
            <li><a href="https://aka.ms/mdi/sizingtool" target="_blank">MDI Sizing Tool Download</a></li>
            <li><a href="https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-proxy" target="_blank">Proxy / Connectivity Configuration</a></li>
          </ul>
        </div>
        <div class="col-md-6">
          <ul style="font-size:13px">
            <li><a href="https://learn.microsoft.com/en-us/defender-for-identity/deploy/create-directory-service-account-gmsa" target="_blank">Configure gMSA Directory Service Account</a></li>
            <li><a href="https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-windows-event-collection" target="_blank">Windows Event Auditing</a></li>
            <li><a href="https://learn.microsoft.com/en-us/defender-for-identity/deploy/install-sensor" target="_blank">Install Sensor v2.x</a></li>
            <li><a href="https://learn.microsoft.com/en-us/defender-for-identity/deploy/activate-sensor" target="_blank">Activate Sensor v3.x</a></li>
            <li><a href="https://learn.microsoft.com/en-us/defender-for-identity/deploy/deploy-sensor-v3#configure-rpc-auditing" target="_blank">v3.x RPC Auditing (Unified Sensor RPC Audit tag)</a></li>
            <li><a href="https://learn.microsoft.com/en-us/defender-for-identity/deploy/active-directory-federation-services" target="_blank">AD FS / AD CS / Entra Connect</a></li>
            <li><a href="https://learn.microsoft.com/en-us/defender-for-identity/deploy/multi-forest" target="_blank">Multi-Forest Considerations</a></li>
            <li><a href="https://github.com/microsoft/Microsoft-Defender-for-Identity/tree/main/Test-MdiReadiness" target="_blank">Test-MdiReadiness Script (GitHub)</a></li>
            <li><a href="https://www.powershellgallery.com/packages/DefenderForIdentity/" target="_blank">DefenderForIdentity PowerShell Module</a></li>
          </ul>
        </div>
      </div>
      <p style="font-size:12px;color:var(--f-text2);margin-top:8px;margin-bottom:0">All references: Microsoft Learn (learn.microsoft.com) — last verified May 2026.</p>
    </div>

  </div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" crossorigin="anonymous"></script>
<script>
  function toggleDone(cb) {
    const body = cb.closest('.fl-checklist-item').querySelector('.item-body');
    if (cb.checked) { body.classList.add('done'); }
    else             { body.classList.remove('done'); }
  }
</script>
</body>
</html>
"@

    $html | Set-Content -Path $filePath -Encoding utf8
    return $filePath
}

#endregion

#region ─── PDF Export ──────────────────────────────────────────────────────

function Export-PlanPdf {
    <#
    .SYNOPSIS
        Generates a PDF from an HTML file using Microsoft Edge's Chrome DevTools Protocol (CDP).
        No external dependencies — requires only Edge (pre-installed on Windows 10/11) and PowerShell 7.
        Uses Page.printToPDF with displayHeaderFooter:false — the same CDP call Playwright makes internally.
    #>
    param ([string] $HtmlPath, [string] $OutputPath)

    $safeName = [System.IO.Path]::GetFileNameWithoutExtension($HtmlPath)
    $pdfPath  = Join-Path $OutputPath "$safeName.pdf"

    # Locate Edge (pre-installed on Windows 10/11)
    $edgePath = @(
        "${env:ProgramFiles}\Microsoft\Edge\Application\msedge.exe",
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1

    if (-not $edgePath) {
        Write-Host '  ⚠  Microsoft Edge not found — skipping PDF generation.' -ForegroundColor Yellow
        return $null
    }

    $debugPort = Get-Random -Minimum 9300 -Maximum 9900
    $fileUri   = 'file:///' + ([System.IO.Path]::GetFullPath($HtmlPath) -replace '\\', '/')

    # Launch Edge headless with remote debugging pointed at about:blank.
    # Using about:blank (not the target page) keeps the WebSocket alive long enough
    # to navigate and print via CDP — direct file:// launch closes the WS on load.
    $proc = Start-Process -FilePath $edgePath -PassThru -RedirectStandardError ([System.IO.Path]::GetTempFileName()) -ArgumentList @(
        '--headless=new', '--disable-gpu', '--no-first-run',
        '--disable-extensions', '--disable-default-apps',
        "--remote-debugging-port=$debugPort", 'about:blank'
    )

    try {
        Write-Host '  Generating PDF (Edge CDP)...' -ForegroundColor Cyan

        # Poll /json/list until Edge is ready (up to 10 s)
        $wsUrl   = $null
        $deadline = [DateTime]::Now.AddSeconds(10)
        while (-not $wsUrl -and [DateTime]::Now -lt $deadline) {
            try {
                $targets = Invoke-RestMethod "http://localhost:$debugPort/json/list" -ErrorAction Stop
                $wsUrl = ($targets | Where-Object type -eq 'page' | Select-Object -First 1).webSocketDebuggerUrl
            } catch { }
            if (-not $wsUrl) { Start-Sleep -Milliseconds 200 }
        }
        if (-not $wsUrl) { throw 'Edge remote debug endpoint did not become available within 10 s.' }

        # Connect WebSocket
        $cts = [System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(90))
        $ws  = [System.Net.WebSockets.ClientWebSocket]::new()
        $null = $ws.ConnectAsync([Uri]$wsUrl, $cts.Token).GetAwaiter().GetResult()

        # Send a CDP command and return its result.
        # Reads and discards event messages (no .id) until the matching command response arrives.
        # Uses a MemoryStream accumulator to handle multi-frame WebSocket messages (required for large PDFs).
        $script:cmdId = 0
        function Invoke-CDP {
            param ([string]$Method, [hashtable]$Params = @{})
            $script:cmdId++
            $id    = $script:cmdId
            $body  = @{ id = $id; method = $Method; params = $Params } | ConvertTo-Json -Depth 10 -Compress
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
            $null = $ws.SendAsync([System.ArraySegment[byte]]$bytes, 'Text', $true, $cts.Token).GetAwaiter().GetResult()

            $chunk = [byte[]]::new(65536)
            do {
                # Accumulate fragmented frames into a single message
                $ms = [System.IO.MemoryStream]::new()
                do {
                    $seg    = [System.ArraySegment[byte]]::new($chunk)
                    $result = $ws.ReceiveAsync($seg, $cts.Token).GetAwaiter().GetResult()
                    $ms.Write($chunk, 0, $result.Count)
                } while (-not $result.EndOfMessage)
                $msg = [System.Text.Encoding]::UTF8.GetString($ms.ToArray()) | ConvertFrom-Json
            } while (-not ($msg.PSObject.Properties['id']) -or $msg.id -ne $id)   # skip CDP events (no .id property)
            return $msg.PSObject.Properties['result'] ? $msg.result : $null
        }

        # Enable Page domain so events are dispatched
        Invoke-CDP -Method 'Page.enable' | Out-Null

        # Navigate to the HTML file and wait for the command response (navigation committed)
        Invoke-CDP -Method 'Page.navigate' -Params @{ url = $fileUri } | Out-Null

        # Allow CSS, fonts and layout to fully settle before printing
        Start-Sleep -Milliseconds 2500

        # Print — same parameters Playwright uses; displayHeaderFooter:false is the key flag
        $pdf = Invoke-CDP -Method 'Page.printToPDF' -Params @{
            printBackground     = $true
            displayHeaderFooter = $false
            paperWidth          = 8.27    # A4 width  in inches
            paperHeight         = 11.69   # A4 height in inches
            marginTop           = 0.59    # ≈ 15 mm
            marginBottom        = 0.59
            marginLeft          = 0.47    # ≈ 12 mm
            marginRight         = 0.47
        }

        $null = $ws.CloseAsync('NormalClosure', '', [System.Threading.CancellationToken]::None).GetAwaiter().GetResult()

        if ($pdf -and $pdf.PSObject.Properties['data'] -and $pdf.data) {
            [System.IO.File]::WriteAllBytes($pdfPath, [System.Convert]::FromBase64String($pdf.data))
            return $pdfPath
        }
        throw 'Page.printToPDF returned no data.'
    }
    catch {
        Write-Host "  ⚠  PDF generation failed: $_" -ForegroundColor Yellow
        return $null
    }
    finally {
        Stop-Process -InputObject $proc -Force -ErrorAction SilentlyContinue
    }
}

#endregion

#region ─── Main ─────────────────────────────────────────────────────────────

# Resolve output path — default to 'Report' subfolder next to the script (predictable regardless of CWD)
if (-not $OutputPath) { $OutputPath = Join-Path $PSScriptRoot 'Report' }
# Always convert to absolute path — .NET static methods (e.g. File::WriteAllBytes) use
# Environment.CurrentDirectory, not PowerShell's working directory, so relative paths break.
$OutputPath = [System.IO.Path]::GetFullPath($OutputPath, (Get-Location).Path)

# Banner
Clear-Host
Write-Host ''
Write-Host '  ┌─────────────────────────────────────────────────────────────────┐' -ForegroundColor Cyan
Write-Host '  │   Microsoft Defender for Identity - Deployment Planner          │' -ForegroundColor Cyan
Write-Host '  │   Invoke-MDIDeploymentPlanner.ps1                               │' -ForegroundColor Cyan
Write-Host '  └─────────────────────────────────────────────────────────────────┘' -ForegroundColor Cyan
Write-Host ''
Write-Host '  Walks through a structured questionnaire and generates a tailored MDI' -ForegroundColor DarkGray
Write-Host '  deployment plan (JSON + HTML). No AD connection required.' -ForegroundColor DarkGray
Write-Host ''

# Detect existing saved plans — scan output folder + legacy Report\ folder next to the script
$scanPaths = @($OutputPath)
$legacyPath = Join-Path $PSScriptRoot 'Report'
if ($legacyPath -ne $OutputPath -and (Test-Path $legacyPath)) { $scanPaths += $legacyPath }

$existingPlans = @(
    $scanPaths | ForEach-Object {
        if (Test-Path $_) { Get-ChildItem -Path $_ -Filter 'MDIDeploymentPlan-*.json' }
    } | Sort-Object LastWriteTime -Descending | Group-Object Name | ForEach-Object { $_.Group[0] }
)

$loadedAnswers = $null

# ── Non-interactive plan load (QA / automation) ─────────────────────────────
if ($PSBoundParameters.ContainsKey('Plan')) {
    if (-not (Test-Path $Plan)) {
        Write-Host "  ✖  Plan file not found: $Plan" -ForegroundColor Red; exit 1
    }
    Write-Host "  Loading plan: $([System.IO.Path]::GetFileName($Plan))" -ForegroundColor DarkGray
    $loadedAnswers = Import-PlanAnswers -JsonPath $Plan
    $CustomerName  = $loadedAnswers.CustomerName
    Write-Host "  Customer    : $CustomerName" -ForegroundColor Cyan
    Write-Host ''
}
elseif ($existingPlans.Count -gt 0) {
    Write-Host '  ┌─────────────────────────────────────────────────────────────────┐' -ForegroundColor DarkCyan
    Write-Host '  │  Saved plans found. Start fresh or resume an existing plan?     │' -ForegroundColor DarkCyan
    Write-Host '  └─────────────────────────────────────────────────────────────────┘' -ForegroundColor DarkCyan
    Write-Host ''
    Write-Host '    [1]  New plan' -ForegroundColor White
    Write-Host '    [2]  Resume existing plan' -ForegroundColor White
    Write-Host ''
    Write-Host '  Choice — press a key, or Enter for default [1]: ' -ForegroundColor DarkGray -NoNewline
    $startChoice = Read-KeyChar -ValidChars @('1','2')
    if ([string]::IsNullOrEmpty($startChoice)) { $startChoice = '1' }
    Write-Host $startChoice -ForegroundColor Cyan
    Write-Host ''

    if ($startChoice -eq '2') {
        Write-Host '  Saved plans:' -ForegroundColor White
        Write-Host ''
        $maxShow = [Math]::Min($existingPlans.Count, 9)
        for ($pi = 0; $pi -lt $maxShow; $pi++) {
            $pf      = $existingPlans[$pi]
            $isDraft = $pf.Name -like '*-DRAFT.json'
            $ts      = $pf.LastWriteTime.ToString('yyyy-MM-dd  HH:mm')
            $label   = if ($isDraft) { "$($pf.Name)  [DRAFT - in progress]" } else { $pf.Name }
            $color   = if ($isDraft) { 'Yellow' } else { 'White' }
            Write-Host ("    [{0}]  {1,-65} {2}" -f ($pi+1), $label, $ts) -ForegroundColor $color
        }
        Write-Host ''
        $validPlanKeys = @(1..$maxShow | ForEach-Object { "$_" })
        if ($maxShow -gt 1) {
            Write-Host "  Choice (1-$maxShow): " -ForegroundColor DarkGray -NoNewline
            $planChoice = Read-KeyChar -ValidChars $validPlanKeys
            Write-Host $planChoice -ForegroundColor Cyan
        } else {
            $planChoice = '1'
            Write-Host '  Loading the only saved plan...' -ForegroundColor DarkGray
        }
        $chosenFile = $existingPlans[[int]$planChoice - 1].FullName
        Write-Host ''
        Write-Host "  Loading: $([System.IO.Path]::GetFileName($chosenFile))" -ForegroundColor DarkGray
        $loadedAnswers = Import-PlanAnswers -JsonPath $chosenFile
        $CustomerName  = $loadedAnswers.CustomerName
        Write-Host "  Customer: $CustomerName" -ForegroundColor Cyan
        Write-Host ''
        Write-Host '  Press any key to open the review screen...' -ForegroundColor DarkGray
        $null = Read-KeyChar -ValidChars @()
    }
}

# Prompt for customer name if not provided (new plan only)
if (-not $loadedAnswers) {
    if (-not $PSBoundParameters.ContainsKey('CustomerName') -or [string]::IsNullOrWhiteSpace($CustomerName)) {
        $rawName = (Read-Host '  Customer or organisation name (used in report title)').Trim()
        $CustomerName = if ([string]::IsNullOrWhiteSpace($rawName)) { 'Customer' } else { $rawName }
    }
}

# Run questionnaire (or resume from review screen)
if ($PSBoundParameters.ContainsKey('Plan')) {
    $answers = $loadedAnswers   # non-interactive: skip questionnaire entirely
} elseif ($loadedAnswers) {
    $answers = Invoke-Questionnaire -LoadedAnswers $loadedAnswers -OutputPath $OutputPath
} else {
    $answers = Invoke-Questionnaire -CustomerName $CustomerName -OutputPath $OutputPath
}

# Build derived data
Write-Host ''
Write-Host '  Building deployment plan...' -ForegroundColor Cyan

# Create output folder only now — avoids leaving an empty folder if the user exits early
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

try {
$serverGroups  = @(Build-ServerGroups   -Answers $answers)
$dsaReqs       = Get-DSARequirements    -Answers $answers
$auditApproach = Get-AuditingApproach   -ServerGroups $serverGroups
$checklist     = @(Build-DeploymentChecklist -Answers $answers -ServerGroups $serverGroups -DSAReqs $dsaReqs -AuditApproach $auditApproach)
$warnings      = @(Get-Warnings         -Answers $answers -ServerGroups $serverGroups)
} catch {
    Write-Host ''
    Write-Host "  ✖  Build failed at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "     $($_.InvocationInfo.Line.Trim())" -ForegroundColor DarkGray
    exit 1
}

# Export outputs
$jsonPath = Export-PlanJson  -Answers $answers -ServerGroups $serverGroups -DSAReqs $dsaReqs `
    -AuditApproach $auditApproach -Checklist $checklist -Warnings $warnings -OutputPath $OutputPath

$htmlPath = New-HtmlReport   -Answers $answers -ServerGroups $serverGroups -DSAReqs $dsaReqs `
    -AuditApproach $auditApproach -Checklist $checklist -Warnings $warnings -OutputPath $OutputPath

# Summary
$totalSensors = 0; $v3Count = 0; $v2Count = 0
foreach ($sg in $serverGroups) {
    $n = [int]$sg['Count']
    $totalSensors += $n
    if ($sg['SensorVersion'] -eq 'v3.x') { $v3Count += $n }
    elseif ($sg['SensorVersion'] -eq 'v2.x') { $v2Count += $n }
}
$blockers = @($warnings | Where-Object { $_.Severity -eq 'BLOCKER' }).Count

Write-Host ''
Write-Host '  ─────────────────────────────────────────────────────────────────' -ForegroundColor Green
Write-Host '  ✓  Deployment plan generated successfully!' -ForegroundColor Green
Write-Host ''
Write-Host "  JSON : $jsonPath" -ForegroundColor White
Write-Host "  HTML : $htmlPath" -ForegroundColor White
Write-Host ''
Write-Host "  Total sensors   : $totalSensors  (v3.x: $v3Count  |  v2.x: $v2Count)" -ForegroundColor Cyan
Write-Host "  Checklist items : $($checklist.Count)" -ForegroundColor Cyan
Write-Host "  Blockers        : $blockers" -ForegroundColor $(if ($blockers -gt 0) { 'Red' } else { 'Green' })
Write-Host ''

# PDF generation
$pdfPath = $null
$generatePdf = -not $NoPdf -and -not $PSBoundParameters.ContainsKey('Plan')
if ($generatePdf -and (Read-YesNo -Prompt 'Generate PDF report as well?' -Default $true)) {
    $pdfPath = @(Export-PlanPdf -HtmlPath $htmlPath -OutputPath $OutputPath) |
               Where-Object { $_ -is [string] -and $_ -match '\.pdf$' } |
               Select-Object -Last 1
    if ($pdfPath) {
        Write-Host "  PDF  : $pdfPath" -ForegroundColor White
    }
    Write-Host ''
}

$openBrowser = $OpenInBrowser -or (-not $PSBoundParameters.ContainsKey('Plan') -and (Read-YesNo -Prompt 'Open HTML report in browser now?' -Default $true))
if ($openBrowser) { Start-Process $htmlPath }

#endregion
