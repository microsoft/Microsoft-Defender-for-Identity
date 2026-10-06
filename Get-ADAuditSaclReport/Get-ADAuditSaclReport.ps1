<#
.SYNOPSIS
    Reports every non-default auditing (SACL) entry on the domain root, OUs and containers.

.DESCRIPTION
    SCOPE
    Reads the SACL of the following objects in a single paged LDAP search (SACL only):
      - The domain root and every organizationalUnit
      - Every container (CN=Users, CN=Computers, CN=System and its children, ...) and
        CN=Builtin
      - The CN=Configuration partition head (that object only, not its children)
    Use -ExcludeContainers to scan only the domain root and OUs.
    Use -SearchBase to limit the scan to part of the domain.

    WHAT COUNTS AS DEFAULT
    An audit entry is treated as default, and left out of the report, when it matches one of:
      1. Schema default: the SACL part of the object class's defaultSecurityDescriptor.
      2. Windows out-of-box defaults: the entries Windows stamps on specific objects when the
         domain is created, from the DC's %windir%\System32\schema.ini template. They cover
         the domain root, CN=Builtin, CN=Configuration, OU=Domain Controllers, and
         CN=AdminSDHolder, CN=DomainUpdates and CN=Policies under CN=System. Each entry is
         matched exactly and only on its own object (see the $builtInSddl table).
      3. Microsoft Defender for Identity (MDI) requirements, as defined in Microsoft's
         Test-MdiReadiness.ps1:
           - Domain root: Everyone / Success on descendant User, Group, Computer, MSA, gMSA
             and dMSA objects
           - CN=Configuration: Everyone / Success+Failure / WriteProperty, this object and
             descendants (Exchange)
           - CN=ADFS,CN=Microsoft,CN=Program Data: Everyone / Success+Failure /
             Read+WriteProperty, this object and descendants
         Like MDI's own check, an entry matches on SID, audit flags and inherited object
         type. If it audits MORE rights than MDI needs, it is still reported and the Notes
         column lists the extra rights. Use -NoMdiExclusions to turn these exclusions off.
      4. Your approved baseline: an optional CSV passed with -BaselinePath.

    WHAT IS REPORTED
    Each output row has a Finding value:
      NonDefault               An explicit audit entry that matched none of the defaults.
      SaclInheritanceDisabled  An object (other than the domain root) whose SACL is
                               protected, so it no longer inherits auditing from its parent.
      InheritedNonDefault      (-IncludeInherited only) An inherited copy of a non-default
                               entry.
      Default                  (-IncludeDefault only) An entry that matched a default. The
                               DefaultSource column says which: Schema, BuiltIn, MDI,
                               Baseline, or Inherited.
    Inherited entries are skipped by default, because each one is reported once on the
    object where it is set explicitly.

    The script needs no ActiveDirectory module; it uses System.DirectoryServices only.

.PARAMETER Server
    DC or domain name to query. Defaults to the current domain.

.PARAMETER SearchBase
    DN to start from. Defaults to the domain root.

.PARAMETER ExcludeContainers
    Scan only the domain root and OUs. By default 'container' objects (CN=Users,
    CN=Computers, CN=System, ...), CN=Builtin and the CN=Configuration object are scanned too.

.PARAMETER IncludeInherited
    Also report inherited ACEs on each object.

.PARAMETER IncludeDefault
    Also output the ACEs that were classified as default (Finding = 'Default').

.PARAMETER BaselinePath
    CSV of approved ACEs. Same columns as this script's output, so the easiest way to build
    one is to run the report, delete the rows you do NOT approve, and feed it back.
    Required columns: IdentitySID, ActiveDirectoryRights, AuditFlags, InheritanceFlags,
    PropagationFlags, ObjectTypeGuid, InheritedObjectTypeGuid.
    Optional: ObjectClass ('*' or blank = any class), DistinguishedName (blank = any object).

.PARAMETER OutputPath
    Export the results to this CSV path.

.PARAMETER NoMdiExclusions
    Do not treat the SACL entries required by Microsoft Defender for Identity as default.

.NOTES
    Permissions: the account must hold "Manage auditing and security log"
    (SeSecurityPrivilege) on the DCs. Domain Admins have it by default. Without it, AD
    silently returns no SACL, so the script stops with a warning instead of reporting
    a clean result.

    With -ExcludeContainers, CN=Configuration and the CN=ADFS container are not scanned, so
    the MDI Exchange and ADFS auditing entries are not checked.

.EXAMPLE
    .\Get-ADAuditSaclReport.ps1 | Out-GridView

    Reports all non-default audit entries in the current domain and shows them in a grid view.

.EXAMPLE
    .\Get-ADAuditSaclReport.ps1 -Server dc01.contoso.com -OutputPath .\sacl.csv

    Queries a specific domain controller and exports the results to a CSV file.

.EXAMPLE
    .\Get-ADAuditSaclReport.ps1 -ExcludeContainers

    Scans only the domain root and the OUs.

.EXAMPLE
    .\Get-ADAuditSaclReport.ps1 -OutputPath .\approved.csv
    .\Get-ADAuditSaclReport.ps1 -BaselinePath .\approved.csv

    Exports the current findings, which you then edit down to the entries you approve, and
    compares later runs against that approved baseline.

.EXAMPLE
    .\Get-ADAuditSaclReport.ps1 -IncludeDefault | Group-Object Finding, DefaultSource | Select-Object Name, Count

    Shows how many audit entries fall into each finding and default source.
#>
[CmdletBinding()]
param(
    [string]$Server,
    [string]$SearchBase,
    [switch]$ExcludeContainers,
    [switch]$IncludeInherited,
    [switch]$IncludeDefault,
    [string]$BaselinePath,
    [string]$OutputPath,
    [switch]$NoMdiExclusions
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

#region Helpers
function Get-LdapPath([string]$DN) {
    if ($Server) { "LDAP://$Server/$DN" } else { "LDAP://$DN" }
}

function New-Searcher([string]$Base, [string]$Filter, [string[]]$Props) {
    $s = New-Object System.DirectoryServices.DirectorySearcher
    $s.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry (Get-LdapPath $Base)
    $s.Filter = $Filter
    $s.PageSize = 1000
    $s.SearchScope = 'Subtree'
    foreach ($p in $Props) { [void]$s.PropertiesToLoad.Add($p) }
    $s
}

$sidCache = @{}
function Resolve-Sid([string]$Sid) {
    if (-not $sidCache.ContainsKey($Sid)) {
        try {
            $sidCache[$Sid] = (New-Object System.Security.Principal.SecurityIdentifier $Sid).
            Translate([System.Security.Principal.NTAccount]).Value
        } catch { $sidCache[$Sid] = $Sid }
    }
    $sidCache[$Sid]
}

function Resolve-Guid([guid]$Guid) {
    if ($Guid -eq [guid]::Empty) { return '(All)' }
    if ($guidMap.ContainsKey($Guid)) { return $guidMap[$Guid] }
    return $Guid.ToString()
}

function Get-AceKey {
    param([string]$Sid, [int]$Rights, [int]$Audit, [int]$Inherit, [int]$Propagate, [guid]$ObjType, [guid]$InhObjType)
    '{0}|{1}|{2}|{3}|{4}|{5}|{6}' -f $Sid.ToUpper(), $Rights, $Audit, $Inherit, $Propagate, $ObjType, $InhObjType
}

function Get-RuleKey($Rule) {
    Get-AceKey -Sid $Rule.IdentityReference.Value -Rights ([int]$Rule.ActiveDirectoryRights) `
        -Audit ([int]$Rule.AuditFlags) -Inherit ([int]$Rule.InheritanceFlags) `
        -Propagate ([int]$Rule.PropagationFlags) -ObjType $Rule.ObjectType -InhObjType $Rule.InheritedObjectType
}

function Get-AppliesTo($Rule) {
    $inh = [int]$Rule.InheritanceFlags
    $prop = $Rule.PropagationFlags
    $target = if ($Rule.InheritedObjectType -ne [guid]::Empty) {
        "descendant $(Resolve-Guid $Rule.InheritedObjectType) objects"
    } else { 'all descendant objects' }

    if ($inh -eq 0) { $text = 'This object only' }
    elseif ($prop -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) {
        $text = $target.Substring(0, 1).ToUpper() + $target.Substring(1)
    } else { $text = "This object and $target" }

    if ($prop -band [System.Security.AccessControl.PropagationFlags]::NoPropagateInherit) { $text += ' (one level only)' }
    $text
}
#endregion

#region Naming contexts
$rootDse = New-Object System.DirectoryServices.DirectoryEntry (Get-LdapPath 'RootDSE')
$domainDN = [string]$rootDse.Properties['defaultNamingContext'].Value
$schemaDN = [string]$rootDse.Properties['schemaNamingContext'].Value
$configDN = [string]$rootDse.Properties['configurationNamingContext'].Value
if (-not $SearchBase) { $SearchBase = $domainDN }
Write-Verbose "Domain: $domainDN  SearchBase: $SearchBase"
#endregion

#region GUID -> name map (schema attributes/classes + extended rights)
Write-Verbose 'Loading schema and extended-rights GUIDs...'
$guidMap = @{}
$classGuidByName = @{}
$classDefaultSddl = @{}

$s = New-Searcher $schemaDN '(schemaIDGUID=*)' @('lDAPDisplayName', 'schemaIDGUID', 'objectClass', 'defaultSecurityDescriptor')
foreach ($r in $s.FindAll()) {
    $name = [string]$r.Properties['ldapdisplayname'][0]
    $g = New-Object System.Guid -ArgumentList (, [byte[]]$r.Properties['schemaidguid'][0])
    $guidMap[$g] = $name
    if ($r.Properties['objectclass'] -contains 'classSchema') {
        $classGuidByName[$name] = $g
        if ($r.Properties['defaultsecuritydescriptor'].Count -gt 0) {
            $classDefaultSddl[$name] = [string]$r.Properties['defaultsecuritydescriptor'][0]
        }
    }
}

$s = New-Searcher "CN=Extended-Rights,$configDN" '(rightsGuid=*)' @('displayName', 'rightsGuid')
foreach ($r in $s.FindAll()) {
    $g = [guid][string]$r.Properties['rightsguid'][0]
    if (-not $guidMap.ContainsKey($g)) { $guidMap[$g] = [string]$r.Properties['displayname'][0] }
}
#endregion

#region Default SACL baselines
# Per-class keys from the schema defaultSecurityDescriptor (S: part)
$schemaDefaults = @{}
function Get-SchemaDefaultKeys([string]$Class) {
    if ($schemaDefaults.ContainsKey($Class)) { return , $schemaDefaults[$Class] }
    $set = New-Object 'System.Collections.Generic.HashSet[string]'
    if ($classDefaultSddl.ContainsKey($Class) -and $classDefaultSddl[$Class] -match 'S:') {
        try {
            $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
            $sd.SetSecurityDescriptorSddlForm($classDefaultSddl[$Class], [System.Security.AccessControl.AccessControlSections]::Audit)
            foreach ($rule in $sd.GetAuditRules($true, $false, [System.Security.Principal.SecurityIdentifier])) {
                [void]$set.Add((Get-RuleKey $rule))
            }
        } catch { Write-Warning "Could not parse defaultSecurityDescriptor for class '$Class': $_" }
    }
    $schemaDefaults[$Class] = $set
    return , $set   # comma stops PowerShell unrolling the HashSet (an empty one would become $null)
}

# Out-of-box SACLs that Windows stamps on specific objects when the domain/forest is created
# (from the DC's %windir%\System32\schema.ini template, NOT from the schema defaultSecurityDescriptor).
# Matched per object (exact DN) and per exact ACE. Aliases: WD=Everyone, BA=BUILTIN\Administrators,
# DU=Domain Users. To verify on a DC:  Select-String -Path $env:windir\System32\schema.ini -Pattern 'S:\('
$gpLinkAce = '(OU;CISA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)'    # gPLink on descendant OUs
$gpOptionsAce = '(OU;CISA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)'    # gPOptions on descendant OUs
$ncHeadSacl = '(AU;SA;WPWDWO;;;WD)(AU;SA;CR;;;BA)(AU;SA;CR;;;DU)'
$builtInSddl = @{
    # Verified against schema.ini (Windows Server; line numbers from one DC, for reference only)
    $domainDN                              = "S:$ncHeadSacl$gpLinkAce$gpOptionsAce"                                # schema.ini:45   domain root
    "CN=Builtin,$domainDN"                 = "S:$ncHeadSacl$gpLinkAce$gpOptionsAce"                                # same template as the domain root (observed on a clean domain)
    $configDN                              = "S:$ncHeadSacl(OU;SA;CR;45ec5156-db7e-47bb-b53f-dbeb2d03c40f;;WD)"    # schema.ini:1473 Configuration NC head (+ Reanimate Tombstones)
    "OU=Domain Controllers,$domainDN"      = 'S:(AU;SA;WDWOCCDCSDDT;;;WD)(AU;CISA;WP;;;WD)'                         # schema.ini:1382
    "CN=AdminSDHolder,CN=System,$domainDN" = 'S:(AU;SA;WDWOWP;;;WD)'                                                # schema.ini:366
    "CN=DomainUpdates,CN=System,$domainDN" = 'S:(AU;CISA;CCDCSDDT;;;WD)'                                            # schema.ini:762
    "CN=Policies,CN=System,$domainDN"      = 'S:(OU;SA;WDWOCCDCSDDT;f30e3bc2-9ff0-11d1-b603-0000f80367c1;;WD)' + # schema.ini:260  create/delete groupPolicyContainer
    '(OU;CISA;WDWP;;f30e3bc2-9ff0-11d1-b603-0000f80367c1;WD)'             #                 write/permissions on GPCs
}
$builtInDefaultsByDN = @{}   # DN -> HashSet of ACE keys (PowerShell hashtables are case-insensitive)
foreach ($dnKey in $builtInSddl.Keys) {
    $set = New-Object 'System.Collections.Generic.HashSet[string]'
    try {
        $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
        $sd.SetSecurityDescriptorSddlForm($builtInSddl[$dnKey], [System.Security.AccessControl.AccessControlSections]::Audit)
        foreach ($rule in $sd.GetAuditRules($true, $false, [System.Security.Principal.SecurityIdentifier])) {
            [void]$set.Add((Get-RuleKey $rule))
        }
    } catch { Write-Warning "Could not parse built-in default SACL for '$dnKey': $_" }
    $builtInDefaultsByDN[$dnKey] = $set
}

# Optional approved baseline
$baseline = @()
if ($BaselinePath) {
    foreach ($row in Import-Csv -Path $BaselinePath) {
        if (-not $row.IdentitySID) { continue }
        $objT = if ($row.ObjectTypeGuid) { [guid]$row.ObjectTypeGuid }          else { [guid]::Empty }
        $inhT = if ($row.InheritedObjectTypeGuid) { [guid]$row.InheritedObjectTypeGuid } else { [guid]::Empty }
        $baseline += [pscustomobject]@{
            ObjectClass       = if ($row.PSObject.Properties['ObjectClass']) { [string]$row.ObjectClass } else { '' }
            DistinguishedName = if ($row.PSObject.Properties['DistinguishedName']) { [string]$row.DistinguishedName } else { '' }
            Key               = Get-AceKey -Sid $row.IdentitySID `
                -Rights ([int][System.DirectoryServices.ActiveDirectoryRights]$row.ActiveDirectoryRights) `
                -Audit ([int][System.Security.AccessControl.AuditFlags]$row.AuditFlags) `
                -Inherit ([int][System.Security.AccessControl.InheritanceFlags]$row.InheritanceFlags) `
                -Propagate ([int][System.Security.AccessControl.PropagationFlags]$row.PropagationFlags) `
                -ObjType $objT -InhObjType $inhT
        }
    }
    Write-Verbose "Loaded $($baseline.Count) baseline entries from $BaselinePath"
}

function Get-DefaultSource([string]$Key, [string]$Class, [string]$DN) {
    if ((Get-SchemaDefaultKeys $Class).Contains($Key)) { return 'Schema' }
    if ($builtInDefaultsByDN.ContainsKey($DN) -and $builtInDefaultsByDN[$DN].Contains($Key)) { return 'BuiltIn' }
    foreach ($b in $baseline) {
        if ($b.Key -ne $Key) { continue }
        if ($b.DistinguishedName -and $b.DistinguishedName -ne $DN) { continue }
        if ($b.ObjectClass -and $b.ObjectClass -ne '*' -and $b.ObjectClass -ne $Class) { continue }
        return 'Baseline'
    }
    return $null
}

# Microsoft Defender for Identity required SACL entries
# Source: github.com/microsoft/Microsoft-Defender-for-Identity/Test-MdiReadiness/Test-MdiReadiness.ps1
#   Rights 852331 = CreateChild, DeleteChild, Self, WriteProperty, DeleteTree, ExtendedRight, Delete, WriteDacl, WriteOwner
#   Rights 852075 = same minus ExtendedRight
#   AceFlags 194 (Exchange/ADFS) = ContainerInherit + Success + Failure  -> this object and all descendants
$mdiAdfsDN = "CN=ADFS,CN=Microsoft,CN=Program Data,$domainDN"
$mdiRequirements = @(
    @{ DN = $domainDN; Rights = 852331; Audit = 1; InhObj = 'bf967aba-0de6-11d0-a285-00aa003049e2'; CI = $false; Desc = 'MDI: descendant User objects' }
    @{ DN = $domainDN; Rights = 852331; Audit = 1; InhObj = 'bf967a9c-0de6-11d0-a285-00aa003049e2'; CI = $false; Desc = 'MDI: descendant Group objects' }
    @{ DN = $domainDN; Rights = 852331; Audit = 1; InhObj = 'bf967a86-0de6-11d0-a285-00aa003049e2'; CI = $false; Desc = 'MDI: descendant Computer objects' }
    @{ DN = $domainDN; Rights = 852331; Audit = 1; InhObj = 'ce206244-5827-4a86-ba1c-1c0c386c1b64'; CI = $false; Desc = 'MDI: descendant msDS-ManagedServiceAccount objects' }
    @{ DN = $domainDN; Rights = 852075; Audit = 1; InhObj = '7b8b558a-93a5-4af7-adca-c017e67f1057'; CI = $false; Desc = 'MDI: descendant msDS-GroupManagedServiceAccount objects' }
    @{ DN = $domainDN; Rights = 852075; Audit = 1; InhObj = '0feb936f-47b3-49f2-9386-1dedc2c23765'; CI = $false; Desc = 'MDI: descendant msDS-DelegatedManagedServiceAccount objects (2025 schema)' }
    @{ DN = $configDN; Rights = 32; Audit = 3; InhObj = '00000000-0000-0000-0000-000000000000'; CI = $true; Desc = 'MDI: Exchange auditing on Configuration container' }
    @{ DN = $mdiAdfsDN; Rights = 48; Audit = 3; InhObj = '00000000-0000-0000-0000-000000000000'; CI = $true; Desc = 'MDI: ADFS container auditing' }
)

# Returns $null, or @{ Exact = $bool; Desc; Extra } when the rule satisfies an MDI requirement
function Get-MdiMatch($Rule, [string]$DN) {
    if ($NoMdiExclusions) { return $null }
    foreach ($m in $mdiRequirements) {
        if ($m.DN -ne $DN) { continue }
        if ($Rule.IdentityReference.Value -ne 'S-1-1-0') { continue }
        if ([int]$Rule.AuditFlags -ne $m.Audit) { continue }
        if ($Rule.InheritedObjectType -ne [guid]$m.InhObj) { continue }
        if ($m.CI -and (([int]$Rule.InheritanceFlags -band 1) -eq 0 -or
                ([int]$Rule.PropagationFlags -band 2))) { continue }   # must be ContainerInherit, not InheritOnly
        $applied = [int]$Rule.ActiveDirectoryRights
        if (($applied -band $m.Rights) -ne $m.Rights) { continue }            # applied must contain the required rights
        $extra = $applied -band (-bnot $m.Rights)
        return @{
            Exact = ($extra -eq 0)
            Desc  = $m.Desc
            Extra = if ($extra) { ([System.DirectoryServices.ActiveDirectoryRights]$extra).ToString() } else { '' }
        }
    }
    return $null
}
#endregion

#region Scan
$classFilter = '(objectCategory=organizationalUnit)(objectClass=domainDNS)'
if (-not $ExcludeContainers) { $classFilter += '(objectCategory=container)(objectClass=builtinDomain)' }

$searchProps = @('distinguishedName', 'objectClass', 'nTSecurityDescriptor')
$searcher = New-Searcher $SearchBase "(|$classFilter)" $searchProps
$searcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Sacl
$searchResults = New-Object System.Collections.Generic.List[object]
foreach ($r in $searcher.FindAll()) { $searchResults.Add($r) }

# CN=Configuration lives in its own partition; read just that object (MDI Exchange auditing lives there)
if (-not $ExcludeContainers) {
    try {
        $cfg = New-Searcher $configDN '(objectClass=*)' $searchProps
        $cfg.SearchScope = 'Base'
        $cfg.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Sacl
        $r = $cfg.FindOne()
        if ($r) { $searchResults.Add($r) }
    } catch { Write-Warning "Could not read $configDN : $_" }
}

$results = New-Object System.Collections.Generic.List[object]
$scanned = 0
$saclSeen = $false
$defaultSigs = New-Object 'System.Collections.Generic.HashSet[string]'   # signatures of default explicit ACEs (to classify their inherited copies)

Write-Verbose 'Scanning objects...'
foreach ($r in $searchResults) {
    $scanned++
    $dn = [string]$r.Properties['distinguishedname'][0]
    $class = [string]($r.Properties['objectclass'] | Select-Object -Last 1)
    if ($r.Properties['ntsecuritydescriptor'].Count -eq 0) { Write-Warning "No security descriptor returned for $dn"; continue }

    [byte[]]$bytes = $r.Properties['ntsecuritydescriptor'][0]
    $raw = New-Object System.Security.AccessControl.RawSecurityDescriptor ($bytes, 0)
    $flags = $raw.ControlFlags
    if ($flags -band [System.Security.AccessControl.ControlFlags]::SystemAclPresent) { $saclSeen = $true }

    $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
    $sd.SetSecurityDescriptorBinaryForm($bytes, [System.Security.AccessControl.AccessControlSections]::Audit)

    # SACL inheritance disabled (not normal for an OU/container)
    if (($flags -band [System.Security.AccessControl.ControlFlags]::SystemAclProtected) -and $class -ne 'domainDNS') {
        $results.Add([pscustomobject][ordered]@{
                DistinguishedName = $dn; ObjectClass = $class; Finding = 'SaclInheritanceDisabled'
                Identity = ''; IdentitySID = ''; AuditFlags = ''; ActiveDirectoryRights = ''
                ObjectTypeName = ''; InheritedObjectTypeName = ''; AppliesTo = ''
                IsInherited = ''; DefaultSource = ''; Notes = ''
                InheritanceFlags = ''; PropagationFlags = ''; ObjectTypeGuid = ''; InheritedObjectTypeGuid = ''
            })
    }

    foreach ($rule in $sd.GetAuditRules($true, [bool]$IncludeInherited, [System.Security.Principal.SecurityIdentifier])) {
        $key = Get-RuleKey $rule
        $src = if ($rule.IsInherited) { $null } else { Get-DefaultSource $key $class $dn }
        $notes = ''
        if (-not $src -and -not $rule.IsInherited) {
            $mdi = Get-MdiMatch $rule $dn
            if ($mdi) {
                if ($mdi.Exact) { $src = 'MDI'; $notes = $mdi.Desc }
                else { $notes = "$($mdi.Desc) - meets the MDI requirement but also audits: $($mdi.Extra)" }
            }
        }
        if ($src) { [void]$defaultSigs.Add("$($rule.IdentityReference.Value)|$($rule.ObjectType)|$($rule.InheritedObjectType)|$($rule.AuditFlags)|$([int]$rule.ActiveDirectoryRights)") }
        if ($src -and -not $IncludeDefault) { continue }

        $sid = $rule.IdentityReference.Value
        $results.Add([pscustomobject][ordered]@{
                DistinguishedName       = $dn
                ObjectClass             = $class
                Finding                 = if ($src) { 'Default' } elseif ($rule.IsInherited) { 'InheritedNonDefault' } else { 'NonDefault' }
                Identity                = Resolve-Sid $sid
                IdentitySID             = $sid
                AuditFlags              = $rule.AuditFlags.ToString()
                ActiveDirectoryRights   = $rule.ActiveDirectoryRights.ToString()
                ObjectTypeName          = Resolve-Guid $rule.ObjectType
                InheritedObjectTypeName = Resolve-Guid $rule.InheritedObjectType
                AppliesTo               = Get-AppliesTo $rule
                IsInherited             = $rule.IsInherited
                DefaultSource           = $src
                Notes                   = $notes
                InheritanceFlags        = $rule.InheritanceFlags.ToString()
                PropagationFlags        = $rule.PropagationFlags.ToString()
                ObjectTypeGuid          = $rule.ObjectType.ToString()
                InheritedObjectTypeGuid = $rule.InheritedObjectType.ToString()
            })
    }
}

if (-not $saclSeen) {
    Write-Warning ("No SACL was returned for any object. The account most likely lacks " +
        "'Manage auditing and security log' (SeSecurityPrivilege) on the DCs. Results are NOT valid.")
    return
}
#endregion

#region Output
# For inherited ACEs that were inherited from a default parent ACE, flag them as Default too
if ($IncludeInherited) {
    # (inheritance/propagation flags change when an ACE is inherited, so they are not part of the signature)
    foreach ($x in $results | Where-Object { $_.Finding -eq 'InheritedNonDefault' }) {
        $rights = [int][System.DirectoryServices.ActiveDirectoryRights]$x.ActiveDirectoryRights
        $sig = "$($x.IdentitySID)|$($x.ObjectTypeGuid)|$($x.InheritedObjectTypeGuid)|$($x.AuditFlags)|$rights"
        if ($defaultSigs.Contains($sig)) { $x.Finding = 'InheritedDefault'; $x.DefaultSource = 'Inherited' }
    }
    if (-not $IncludeDefault) { $results = @($results | Where-Object { $_.Finding -ne 'InheritedDefault' }) }
}

$nonDefault = @($results | Where-Object { $_.Finding -in 'NonDefault', 'InheritedNonDefault', 'SaclInheritanceDisabled' })
Write-Host ("Scanned {0} objects. Non-default findings: {1} on {2} object(s)." -f `
        $scanned, $nonDefault.Count, @($nonDefault | Select-Object -ExpandProperty DistinguishedName -Unique).Count) -ForegroundColor Cyan

if ($OutputPath) {
    $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host "Report written to $OutputPath" -ForegroundColor Cyan
}

$results
#endregion