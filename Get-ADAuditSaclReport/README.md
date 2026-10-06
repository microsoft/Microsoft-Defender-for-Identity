# Get-ADAuditSaclReport.ps1

The `Get-ADAuditSaclReport.ps1` script traverses the Active Directory domain
root, OUs and containers, reads the auditing settings (SACL) on each object, and
reports every audit entry that is **not** part of the default configuration. Use
it to find custom auditing someone added over the years, to confirm the
**Microsoft Defender for Identity** auditing requirements are applied without
extra noise, or to compare the current state against an approved baseline.

It scans the following objects:

- The domain root and every organizational unit
- Every container (`CN=Users`, `CN=Computers`, `CN=System` and its children,
  ...) and `CN=Builtin`, unless `-ExcludeContainers` is used
- The `CN=Configuration` partition head (that object only), unless
  `-ExcludeContainers` is used

An audit entry is treated as default, and left out of the report, when it
matches any of the following:

- **Schema default** — the SACL part of the object class's
  `defaultSecurityDescriptor` in the AD schema
- **Windows out-of-box defaults** — the entries Windows stamps on specific
  objects when the domain is created, from the domain controller's
  `%windir%\System32\schema.ini` template. They cover the domain root,
  `CN=Builtin`, `CN=Configuration`, `OU=Domain Controllers`, and
  `CN=AdminSDHolder`, `CN=DomainUpdates` and `CN=Policies` under `CN=System`.
  Each entry is matched exactly and only on its own object.
- **Microsoft Defender for Identity requirements**, as checked by
  [Test-MdiReadiness.ps1](../Test-MdiReadiness):
  - [Object Auditing](https://aka.ms/mdi/objectauditing)
  - [Exchange Auditing](https://aka.ms/mdi/exchangeauditing)
  - [ADFS Auditing](https://aka.ms/mdi/adfsauditing)

  Like `Test-MdiReadiness.ps1`, an entry matches on SID, audit flags and
  inherited object type. An entry that audits **more** rights than MDI needs is
  still reported, and the `Notes` column lists the extra rights. Use
  `-NoMdiExclusions` to turn these exclusions off.
- **Your approved baseline** — an optional CSV passed with `-BaselinePath`. It
  uses the same columns as the script's output, so the easiest way to build one
  is to export a report, delete the rows you do not approve, and pass the file
  back.

Inherited entries are skipped by default, because each one is reported once on
the object where it is set explicitly. Use `-IncludeInherited` to see them on
every child object.

The script emits `PSCustomObject` result objects to the pipeline, so results can
be piped, filtered, formatted or exported by the caller. It also writes a
one-line summary to the host, and can export the results to CSV with
`-OutputPath`.

Each result has one of the following `Finding` values:

| Finding | Description |
|---|---|
| `NonDefault` | An explicit audit entry that matched none of the defaults |
| `SaclInheritanceDisabled` | An object (other than the domain root) whose SACL is protected, so it no longer inherits auditing from its parent |
| `InheritedNonDefault` | An inherited copy of a non-default entry. Only with `-IncludeInherited` |
| `Default` | An entry that matched a default. Only with `-IncludeDefault`. The `DefaultSource` column says which default it matched |

Each output object contains the following properties:

| Property | Description |
|---|---|
| `DistinguishedName` | The object the audit entry is set on |
| `ObjectClass` | The object's most specific object class (e.g. `organizationalUnit`, `container`, `domainDNS`) |
| `Finding` | `NonDefault`, `SaclInheritanceDisabled`, `InheritedNonDefault` or `Default` (see above) |
| `Identity` | The audited security principal, resolved to a name (e.g. `Everyone`, `CONTOSO\Domain Users`) |
| `IdentitySID` | The audited security principal's SID |
| `AuditFlags` | `Success`, `Failure`, or `Success, Failure` |
| `ActiveDirectoryRights` | The audited AD right(s) (e.g. `WriteProperty`, `WriteDacl`, `ExtendedRight`) |
| `ObjectTypeName` | Attribute, class or extended right the entry targets, resolved from the schema GUID; `(All)` if the GUID is empty |
| `InheritedObjectTypeName` | Object class the entry propagates to, resolved from the schema GUID; `(All)` if the GUID is empty |
| `AppliesTo` | Scope in the same wording as the Advanced Security Settings dialog (e.g. `This object only`, `This object and all descendant objects`, `Descendant user objects`) |
| `IsInherited` | `$true` if the entry was inherited from a parent object |
| `DefaultSource` | For default entries, which default matched: `Schema`, `BuiltIn`, `MDI`, `Baseline` or `Inherited` |
| `Notes` | Additional detail, e.g. which MDI requirement an entry covers and any extra rights it audits |
| `InheritanceFlags` | Raw inheritance flags (`None`, `ContainerInherit`, ...) |
| `PropagationFlags` | Raw propagation flags (`None`, `InheritOnly`, `NoPropagateInherit`) |
| `ObjectTypeGuid` | Raw object type GUID |
| `InheritedObjectTypeGuid` | Raw inherited object type GUID |

```txt
NAME
    .\Get-ADAuditSaclReport.ps1

SYNOPSIS
    Reports every non-default auditing (SACL) entry on the domain root, OUs and containers.

SYNTAX
    .\Get-ADAuditSaclReport.ps1 [[-Server] <String>] [[-SearchBase] <String>] [-ExcludeContainers]
        [-IncludeInherited] [-IncludeDefault] [[-BaselinePath] <String>] [[-OutputPath] <String>]
        [-NoMdiExclusions] [<CommonParameters>]

DESCRIPTION
    Reads the SACL of the domain root, every OU, every container, CN=Builtin and the
    CN=Configuration object in a single paged LDAP search, and reports every audit entry that
    does not match the schema defaults, the Windows out-of-box defaults (schema.ini), the
    Microsoft Defender for Identity auditing requirements, or an optional approved baseline.
    It also reports objects whose SACL inheritance has been disabled.

PARAMETERS
    -Server <String>
        DC or domain name to query. Defaults to the current domain.

        Required?                    false
        Position?                    1
        Default value
        Accept pipeline input?       false
        Accept wildcard characters?  false

    -SearchBase <String>
        DN to start from. Defaults to the domain root.

        Required?                    false
        Position?                    2
        Default value
        Accept pipeline input?       false
        Accept wildcard characters?  false

    -ExcludeContainers [<SwitchParameter>]
        Scan only the domain root and OUs. By default 'container' objects (CN=Users,
        CN=Computers, CN=System, ...), CN=Builtin and the CN=Configuration object are scanned too.

        Required?                    false
        Position?                    named
        Default value                False
        Accept pipeline input?       false
        Accept wildcard characters?  false

    -IncludeInherited [<SwitchParameter>]
        Also report inherited ACEs on each object.

        Required?                    false
        Position?                    named
        Default value                False
        Accept pipeline input?       false
        Accept wildcard characters?  false

    -IncludeDefault [<SwitchParameter>]
        Also output the ACEs that were classified as default (Finding = 'Default').

        Required?                    false
        Position?                    named
        Default value                False
        Accept pipeline input?       false
        Accept wildcard characters?  false

    -BaselinePath <String>
        CSV of approved ACEs. Same columns as this script's output, so the easiest way to build
        one is to run the report, delete the rows you do NOT approve, and feed it back.
        Required columns: IdentitySID, ActiveDirectoryRights, AuditFlags, InheritanceFlags,
        PropagationFlags, ObjectTypeGuid, InheritedObjectTypeGuid.
        Optional: ObjectClass ('*' or blank = any class), DistinguishedName (blank = any object).

        Required?                    false
        Position?                    3
        Default value
        Accept pipeline input?       false
        Accept wildcard characters?  false

    -OutputPath <String>
        Export the results to this CSV path.

        Required?                    false
        Position?                    4
        Default value
        Accept pipeline input?       false
        Accept wildcard characters?  false

    -NoMdiExclusions [<SwitchParameter>]
        Do not treat the SACL entries required by Microsoft Defender for Identity as default.

        Required?                    false
        Position?                    named
        Default value                False
        Accept pipeline input?       false
        Accept wildcard characters?  false

NOTES
    Permissions: the account must hold "Manage auditing and security log"
    (SeSecurityPrivilege) on the DCs. Domain Admins have it by default. Without it, AD
    silently returns no SACL, so the script stops with a warning instead of reporting
    a clean result.

    With -ExcludeContainers, CN=Configuration and the CN=ADFS container are not scanned, so
    the MDI Exchange and ADFS auditing entries are not checked.

    -------------------------- EXAMPLE 1 --------------------------

    PS C:\>.\Get-ADAuditSaclReport.ps1 | Out-GridView

    Reports all non-default audit entries in the current domain and shows them in a grid view.

    -------------------------- EXAMPLE 2 --------------------------

    PS C:\>.\Get-ADAuditSaclReport.ps1 -Server dc01.contoso.com -OutputPath .\sacl.csv

    Queries a specific domain controller and exports the results to a CSV file.

    -------------------------- EXAMPLE 3 --------------------------

    PS C:\>.\Get-ADAuditSaclReport.ps1 -ExcludeContainers

    Scans only the domain root and the OUs.

    -------------------------- EXAMPLE 4 --------------------------

    PS C:\>.\Get-ADAuditSaclReport.ps1 -OutputPath .\approved.csv
    PS C:\>.\Get-ADAuditSaclReport.ps1 -BaselinePath .\approved.csv

    Exports the current findings, which you then edit down to the entries you approve, and
    compares later runs against that approved baseline.

    -------------------------- EXAMPLE 5 --------------------------

    PS C:\>.\Get-ADAuditSaclReport.ps1 -IncludeDefault | Group-Object Finding, DefaultSource | Select-Object Name, Count

    Shows how many audit entries fall into each finding and default source.
```

PREREQUISITES

| Requirement | Details |
|---|---|
| PowerShell | Windows PowerShell 5.1 or PowerShell 7+ on Windows |
| ActiveDirectory module | Not required — the script uses `System.DirectoryServices` only |
| Permissions | The running account must hold **Manage auditing and security log** (`SeSecurityPrivilege`) on the domain controllers to read SACLs. Domain Admins have it by default. |
| Network | LDAP access to a domain controller of the target domain |