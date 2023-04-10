<#
    .NOTES
        Copyright (c) Microsoft Corporation.  All rights reserved.
        Use of this sample source code is subject to the terms of the Microsoft
        license agreement under which you licensed this sample source code. If
        you did not accept the terms of the license agreement, you are not
        authorized to use this sample source code. For the terms of the license,
        please see the license agreement between you and Microsoft or, if applicable,
        see the LICENSE.RTF on your install media or the root of your tools installation.
        THE SAMPLE SOURCE CODE IS PROVIDED "AS IS", WITH NO WARRANTIES.
    .SYNOPSIS
        Verifies Microsoft Defender for Identity prerequisites are in place
    .DESCRIPTION
        This script will query your domain and report if the different Microsoft Defender for Identity prerequisites are in place. It creates an html report and a detailed json file with all the collected data.
    .PARAMETER Path
        Path to a folder where the reports are be saved
    .PARAMETER Domain
        Domain Name or FQDN to work against. Defaults to current domain
    .PARAMETER OpenHtmlReport
        Open the HTML report at the end of the collection process
    .EXAMPLE
        .\Test-MdiReadiness.ps1 -OpenHtmlReport
    .EXAMPLE
        .\Test-MdiReadiness.ps1 -Verbose
#>

#Requires -Version 4.0
#requires -Module ActiveDirectory

[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [Parameter(Mandatory = $false, HelpMessage = 'Path to a folder where the reports are be saved')]
    [string] $Path = '.',
    [Parameter(Mandatory = $false, HelpMessage = 'Domain Name or FQDN to work against. Defaults to current domain')]
    [string] $Domain = $null,
    [Parameter(Mandatory = $false, HelpMessage = 'Open the HTML report at the end of the collection process')]
    [switch] $OpenHtmlReport
)


#region Helper functions


function Invoke-mdiRemoteCommand {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName,
        [Parameter(Mandatory = $true)] [string] $CommandLine,
        [Parameter(Mandatory = $false)] [string] $LocalFile = $null
    )

    $wmiParams = @{
        ComputerName = $ComputerName
        Namespace    = 'root\cimv2'
        Class        = 'Win32_Process'
        Name         = 'Create'
        ErrorAction  = 'SilentlyContinue'
    }
    if ($LocalFile -eq [string]::Empty) {
        $LocalFile = 'C:\Windows\Temp\mdi-{0}.tmp' -f [guid]::NewGuid().GUID
        $wmiParams['ArgumentList'] = '{0} 2>&1>{1}' -f $CommandLine, $LocalFile
    } else {
        $wmiParams['ArgumentList'] = $CommandLine
    }

    $result = Invoke-WmiMethod @wmiParams
    $maxWait = [datetime]::Now.AddSeconds(15)

    $waitForProcessParams = @{
        ComputerName = $ComputerName
        Namespace    = 'root\cimv2'
        Class        = 'Win32_Process'
        Filter       = ("ProcessId='{0}'" -f $result.ProcessId)
    }

    if ($result.ReturnValue -eq 0) {
        do { Start-Sleep -Milliseconds 200 }
        while (([datetime]::Now -lt $maxWait) -and (Get-WmiObject @waitForProcessParams).CommandLine -eq $wmiParams.ArgumentList)
    }

    try {
        # Read the file using SMB
        $remoteFile = $LocalFile -replace 'C:', ('\\{0}\C$' -f $ComputerName)
        $return = Get-Content -Path $remoteFile -ErrorAction Stop
        Remove-Item -Path $remoteFile -Force
    } catch {
        try {
            # Read the remote file using WMI
            $psmClassParams = @{
                Namespace    = 'root\Microsoft\Windows\Powershellv3'
                ClassName    = 'PS_ModuleFile'
                ComputerName = $ComputerName
            }
            $cimParams = @{
                CimClass   = Get-CimClass @psmClassParams
                Property   = @{ InstanceID = $LocalFile }
                ClientOnly = $true
            }
            $fileInstanceParams = @{
                InputObject  = New-CimInstance @cimParams
                ComputerName = $ComputerName
            }
            $fileContents = Get-CimInstance @fileInstanceParams -ErrorAction Stop
            $fileLengthBytes = $fileContents.FileData[0..3]
            [array]::Reverse($fileLengthBytes)
            $fileLength = [BitConverter]::ToUInt32($fileLengthBytes, 0)
            $fileBytes = $fileContents.FileData[4..($fileLength - 1)]
            $localTempFile = [System.IO.Path]::GetTempFileName()
            Set-Content -Value $fileBytes -Encoding Byte -Path $localTempFile
            $return = Get-Content -Path $localTempFile
            Remove-Item -Path $localTempFile -Force
        } catch {
            $return = $null
        }
    }
    $return
}


function Get-mdiPowerScheme {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName
    )

    $commandLine = 'cmd.exe /c %windir%\system32\powercfg.exe /getactivescheme'
    $details = Invoke-mdiRemoteCommand -ComputerName $ComputerName -CommandLine $commandLine
    if ($details -match ':\s+(?<guid>[a-fA-F0-9]{8}[-]?([a-fA-F0-9]{4}[-]?){3}[a-fA-F0-9]{12})\s+\((?<name>.*)\)') {
        $return = [pscustomobject]@{
            isPowerSchemeOk = $Matches.guid -eq '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'
            details         = $details
        }
    } else {
        $return = [pscustomobject]@{
            isPowerSchemeOk = $false
            details         = $details
        }
    }
    $return
}


function Get-mdiServerRequirements {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName
    )
    $csiParams = @{
        ComputerName = $ComputerName
        Namespace    = 'root\cimv2'
        Class        = 'Win32_ComputerSystem'
        Property     = 'NumberOfLogicalProcessors', 'TotalPhysicalMemory'
        ErrorAction  = 'SilentlyContinue'
    }
    $csi = Get-WmiObject @csiParams

    $osParams = @{
        ComputerName = $ComputerName
        Namespace    = 'root\cimv2'
        Class        = 'Win32_OperatingSystem'
        Property     = 'SystemDrive'
        ErrorAction  = 'SilentlyContinue'
    }
    $osdiskParams = @{
        ComputerName = $ComputerName
        Namespace    = 'root\cimv2'
        Class        = 'Win32_LogicalDisk'
        Property     = 'FreeSpace', 'DeviceID'
        Filter       = "DeviceID = '{0}'" -f (Get-WmiObject @osParams).SystemDrive
        ErrorAction  = 'SilentlyContinue'
    }
    $osdisk = Get-WmiObject @osdiskParams


    $return = [pscustomobject]@{
        isMinHwRequirementsOk = ($csi.NumberOfLogicalProcessors -ge 2) -and ($csi.TotalPhysicalMemory -ge 6gb) -and ($osdisk.FreeSpace -ge 6gb)
        details               = [pscustomobject]@{
            NumberOfLogicalProcessors = $csi.NumberOfLogicalProcessors
            TotalPhysicalMemory       = $csi.TotalPhysicalMemory
            OsDiskDeviceID            = $osdisk.DeviceID
            OsDiskFreeSpace           = $osdisk.FreeSpace
        }
    }
    $return
}


function Get-mdiRegitryValueSet {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName,
        [Parameter(Mandatory = $true)] [string[]] $ExpectedRegistrySet
    )

    $hklm = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName, 'Registry64')
    $details = foreach ($reg in $ExpectedRegistrySet) {

        $regKeyPath, $regValue, $expectedValue = $reg -split ','
        $regKey = $hklm.OpenSubKey($regKeyPath)
        $value = $regKey.GetValue($regValue)

        [pscustomobject]@{
            regKey        = '{0}\{1}' -f $regKeyPath, $regValue
            value         = $value
            expectedValue = $expectedValue
        }
    }

    $hklm.Close()
    $details
}


function Get-mdiNtlmAuditing {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName
    )

    $expectedRegistrySet = @(
        'System\CurrentControlSet\Control\Lsa\MSV1_0,AuditReceivingNTLMTraffic,2',
        'System\CurrentControlSet\Control\Lsa\MSV1_0,RestrictSendingNTLMTraffic,1|2',
        'System\CurrentControlSet\Services\Netlogon\Parameters,AuditNTLMInDomain,7'
    )

    $details = Get-mdiRegitryValueSet -ComputerName $ComputerName -ExpectedRegistrySet $expectedRegistrySet
    $return = [pscustomobject]@{
        isNtlmAuditingOk = @($details | Where-Object { $_.value -notmatch $_.expectedValue }).Count -eq 0
        details          = $details | Select-Object regKey, value
    }
    $return
}


function Get-mdiCertReadiness {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName
    )

    $expectedRootCertificates = @(
        'D4DE20D05E66FC53FE1A50882C78DB2852CAE474'   # All customers, Baltimore CyberTrust Root
        , 'DF3C24F9BFD666761B268073FE06D1CC8D4F82A4' # Commercial, DigiCert Global Root G2
        , 'A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436' # USGov, DigiCert Global Root CA
    )
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("\\$ComputerName\Root",
        [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    $details = $store.Certificates | Where-Object { $expectedRootCertificates -contains $_.Thumbprint }
    $store.Close()
    $return = [pscustomobject]@{
        isRootCertificatesOk = @($details).Count -gt 1
        details              = $details | Select-Object -Property Thumbprint, Subject, Issuer, NotBefore, NotAfter
    }
    $return
}


function Get-mdiCaptureComponent {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName
    )
    $uninstallRegKey = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall'
    $return = @()
    try {
        foreach ($registryView in @('Registry32', 'Registry64')) {
            $hklm = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName, $registryView)
            $uninstallRef = $hklm.OpenSubKey($uninstallRegKey)
            $applications = $uninstallRef.GetSubKeyNames()

            foreach ($app in $applications) {
                $appDetails = $hklm.OpenSubKey($uninstallRegKey + '\' + $app)
                $appDisplayName = $appDetails.GetValue('DisplayName')
                $appVersion = $appDetails.GetValue('DisplayVersion')
                if ($appDisplayName -match 'npcap|winpcap') {
                    $return += '{0} ({1})' -f $appDisplayName, $appVersion
                }
            }
            $hklm.Close()
        }
    } catch {
        $return = 'N/A'
    }
    ($return -join ', ')
}


function Get-mdiSensorVersion {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName
    )
    try {
        $serviceParams = @{
            ComputerName = $ComputerName
            Namespace    = 'root\cimv2'
            Class        = 'Win32_Service'
            Property     = 'Name', 'PathName', 'State'
            Filter       = "Name = 'AATPSensor'"
            ErrorAction  = 'SilentlyContinue'
        }
        $service = Get-WmiObject @serviceParams
        if ($service) {
            $versionParams = @{
                ComputerName = $ComputerName
                Namespace    = 'root\cimv2'
                Class        = 'CIM_DataFile'
                Property     = 'Version'
                Filter       = 'Name={0}' -f ($service.PathName -replace '\\', '\\')
                ErrorAction  = 'SilentlyContinue'
            }
            $return = (Get-WmiObject @versionParams).Version
        } else {
            $return = 'N/A'
        }
    } catch {
        $return = 'N/A'
    }
    $return
}


function Get-mdiMachineType {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName
    )
    $csiParams = @{
        ComputerName = $ComputerName
        Namespace    = 'root\cimv2'
        Class        = 'Win32_ComputerSystem'
        Property     = 'Model', 'Manufacturer'
        ErrorAction  = 'SilentlyContinue'
    }
    $csi = Get-WmiObject @csiParams
    switch ($csi.Model) {
        { $_ -eq 'Virtual Machine' } { 'Hyper-V'; break }
        { $_ -match 'VMware|VirtualBox' } { $_; break }
        default {
            switch ($csi.Manufacturer) {
                { $_ -match 'Xen|Google' } { $_; break }
                { $_ -match 'QEMU' } { 'KVM'; break }
                { $_ -eq 'Microsoft Corporation' } {
                    $azgaParams = @{
                        ComputerName = $ComputerName
                        Namespace    = 'root\cimv2'
                        Class        = 'Win32_Service'
                        Filter       = "Name = 'WindowsAzureGuestAgent'"
                        ErrorAction  = 'SilentlyContinue'
                    }
                    if (Get-WmiObject @azgaParams) { 'Azure' } else { 'Hyper-V' }
                    break
                }
                default {
                    $cspParams = @{
                        ComputerName = $ComputerName
                        Namespace    = 'root\cimv2'
                        Class        = 'Win32_ComputerSystemProduct'
                        Property     = 'uuid'
                        ErrorAction  = 'SilentlyContinue'
                    }
                    $uuid = (Get-WmiObject @cspParams).UUID
                    if ($uuid -match '^EC2') { 'AWS' }
                    else { 'Physical' }
                }
            }
        }
    }
}


function Get-mdiOSVersion {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName
    )
    try {
        $osParams = @{
            ComputerName = $ComputerName
            Namespace    = 'root\cimv2'
            Class        = 'Win32_OperatingSystem'
            Property     = 'Version', 'Caption'
            ErrorAction  = 'SilentlyContinue'
        }
        $os = Get-WmiObject @osParams
        $return = [pscustomobject]@{
            isOsVerOk = [version]($os.Version) -ge [version]('6.3')
            details   = [pscustomobject]@{
                Caption = $os.Caption
                Version = $os.Version
            }
        }
    } catch {
        $return = [pscustomobject]@{
            isOsVerOk = $false
            details   = [pscustomobject]@{
                Caption = 'N/A'
                Version = 'N/A'
            }
        }
    }
    $return
}


function Get-mdiAdvancedAuditing {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName
    )

    $expectedAuditing = @'
Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Setting Value
System,Security System Extension,{0CCE9211-69AE-11D9-BED3-505054503030},Success and Failure,3
System,Distribution Group Management,{0CCE9238-69AE-11D9-BED3-505054503030},Success and Failure,3
System,Security Group Management,{0CCE9237-69AE-11D9-BED3-505054503030},Success and Failure,3
System,Computer Account Management,{0CCE9236-69AE-11D9-BED3-505054503030},Success and Failure,3
System,User Account Management,{0CCE9235-69AE-11D9-BED3-505054503030},Success and Failure,3
System,Directory Service Access,{0CCE923B-69AE-11D9-BED3-505054503030},Success and Failure,3
System,Directory Service Changes,{0CCE923C-69AE-11D9-BED3-505054503030},Success and Failure,3
System,Credential Validation,{0CCE923F-69AE-11D9-BED3-505054503030},Success and Failure,3
'@ | ConvertFrom-Csv
    $properties = ($expectedAuditing | Get-Member -MemberType NoteProperty).Name

    $LocalFile = 'C:\Windows\Temp\mdi-{0}.csv' -f [guid]::NewGuid().Guid
    $commandLine = 'cmd.exe /c auditpol.exe /backup /file:{0}' -f $LocalFile
    $output = Invoke-mdiRemoteCommand -ComputerName $ComputerName -CommandLine $commandLine -LocalFile $LocalFile
    if ($output) {
        $advancedAuditing = $output | ConvertFrom-Csv | Where-Object {
            $_.Subcategory -in $expectedAuditing.Subcategory
        } | Select-Object -Property $properties

        $compareParams = @{
            ReferenceObject  = $expectedAuditing
            DifferenceObject = $advancedAuditing
            Property         = $properties
        }
        $isAdvancedAuditingOk = $null -eq (Compare-Object @compareParams)
        $return = [pscustomobject]@{
            isAdvancedAuditingOk = $isAdvancedAuditingOk
            details              = $advancedAuditing
        }
    } else {
        $return = [pscustomobject]@{
            isAdvancedAuditingOk = $false
            details              = 'Unable to get the advanced auditing settings remotely'
        }
    }
    $return
}


function Get-mdiDsSacl {
    param (
        [Parameter(Mandatory = $true)] [string] $LdapPath,
        [Parameter(Mandatory = $true)] [object[]] $ExpectedAuditing
    )

    $searcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList ([adsi]$LdapPath)
    $searcher.CacheResults = $false
    $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Base
    $searcher.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All
    $searcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Sacl
    $searcher.PropertiesToLoad.AddRange(('ntsecuritydescriptor,distinguishedname,objectsid' -split ','))
    try {
        $result = ($searcher.FindOne()).Properties

        $appliedAuditing = New-Object -TypeName Security.AccessControl.RawSecurityDescriptor -ArgumentList ($result['ntsecuritydescriptor'][0], 0) |
            ForEach-Object { $_.SystemAcl } | Select-Object *,
            @{N = 'AccessMaskDetails'; E = { (([Enum]::ToObject([System.DirectoryServices.ActiveDirectoryRights], $_.AccessMask))).ToString() } },
            @{N = 'AuditFlagsValue'; E = { $_.AuditFlags.value__ } },
            @{N = 'AceFlagsValue'; E = { $_.AceFlags.value__ } }


        $properties = ($expectedAuditing | Get-Member -MemberType NoteProperty).Name
        $compareParams = @{
            ReferenceObject  = $expectedAuditing | Select-Object -Property $properties
            DifferenceObject = $appliedAuditing | Select-Object -Property $properties
            Property         = $properties
        }

        $return = [pscustomobject]@{
            isAuditingOk = @(Compare-Object @compareParams -ExcludeDifferent -IncludeEqual).Count -eq $expectedAuditing.Count
            details      = $appliedAuditing
        }
    } catch {
        $e = $_
        $return = [pscustomobject]@{
            isAuditingOk = if ($e.Exception.InnerException.ErrorCode -eq -2147016656) { 'N/A' } else { $false }
            details      = if ($e.Exception.InnerException.Message) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
        }
    }
    $return
}


function Get-mdiObjectAuditing {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)] [string] $Domain
    )

    Write-Verbose -Message 'Getting MDI related DS Object auditing configuration'
    $expectedAuditing = @'
SecurityIdentifier,AccessMask,AuditFlagsValue,InheritedObjectAceType,Description
S-1-1-0,852331,1,bf967aba-0de6-11d0-a285-00aa003049e2,Descendant User Objects
S-1-1-0,852331,1,bf967a9c-0de6-11d0-a285-00aa003049e2,Descendant Group Objects
S-1-1-0,852331,1,bf967a86-0de6-11d0-a285-00aa003049e2,Descendant Computer Objects
S-1-1-0,852331,1,ce206244-5827-4a86-ba1c-1c0c386c1b64,Descendant msDS-ManagedServiceAccount Objects
S-1-1-0,852075,1,7b8b558a-93a5-4af7-adca-c017e67f1057,Descendant msDS-GroupManagedServiceAccount Objects
'@ | ConvertFrom-Csv | Select-Object SecurityIdentifier, AccessMask, AuditFlagsValue, InheritedObjectAceType

    $ds = [adsi]('LDAP://{0}/ROOTDSE' -f $Domain)
    $ldapPath = 'LDAP://{0}' -f $ds.defaultNamingContext.Value

    $result = Get-mdiDsSacl -LdapPath $ldapPath -ExpectedAuditing $expectedAuditing
    $appliedAuditing = $result.details

    $isAuditingOk = @(foreach ($applied in $appliedAuditing) {
            $expectedAuditing | Where-Object { ($_.SecurityIdentifier -eq $applied.SecurityIdentifier) -and ($_.AuditFlagsValue -eq $applied.AuditFlagsValue) -and
        ($_.InheritedObjectAceType -eq $applied.InheritedObjectAceType) -and
            (([System.DirectoryServices.ActiveDirectoryRights]$applied.AccessMask).HasFlag(([System.DirectoryServices.ActiveDirectoryRights]($_.AccessMask)))) }
        }).Count -eq $expectedAuditing.Count

    $return = @{
        isObjectAuditingOk = $isAuditingOk
        details            = $result.details
    }
    $return
}


function Get-mdiExchangeAuditing {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)] [string] $Domain,
        [Parameter(Mandatory = $false)] [string] $DSAuditContainer = $null
    )

    Write-Verbose -Message 'Getting MDI related Exchange auditing configuration'

    $expectedAuditing = @'
SecurityIdentifier,AccessMask,AuditFlagsValue,AceFlagsValue
S-1-1-0,32,3,194
'@ | ConvertFrom-Csv

    $ds = [adsi]('LDAP://{0}/ROOTDSE' -f $Domain)
    $ldapPath = 'LDAP://CN=Configuration,{0}' -f $ds.defaultNamingContext.Value

    $result = Get-mdiDsSacl -LdapPath $ldapPath -ExpectedAuditing $expectedAuditing
    $return = @{
        isExchangeAuditingOk = $result.isAuditingOk
        details              = $result.details
    }
    $return

}


function Get-mdiAdfsAuditing {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)] [string] $Domain
    )

    Write-Verbose -Message 'Getting MDI related ADFS auditing configuration'

    $expectedAuditing = @'
SecurityIdentifier,AccessMask,AuditFlagsValue,AceFlagsValue
S-1-1-0,48,3,194
'@ | ConvertFrom-Csv

    $ds = [adsi]('LDAP://{0}/ROOTDSE' -f $Domain)
    $ldapPath = 'LDAP://CN=ADFS,CN=Microsoft,CN=Program Data,{0}' -f $ds.defaultNamingContext.Value

    $result = Get-mdiDsSacl -LdapPath $ldapPath -ExpectedAuditing $expectedAuditing
    $return = @{
        isAdfsAuditingOk = $result.isAuditingOk
        details          = $result.details
    }
    $return
}


function Get-DomainSchemaVersion {
    [CmdletBinding(SupportsShouldProcess = $false)]
    param (
        [Parameter(Mandatory = $true)] [string] $Domain
    )
    $schemaVersions = @{
        13 = 'Windows 2000 Server'
        30 = 'Windows Server 2003'
        31 = 'Windows Server 2003 R2'
        44 = 'Windows Server 2008'
        47 = 'Windows Server 2008 R2'
        56 = 'Windows Server 2012'
        69 = 'Windows Server 2012 R2'
        87 = 'Windows Server 2016'
        88 = 'Windows Server 2019 / 2022'
    }

    Write-Verbose -Message 'Getting AD Schema Version'
    $schema = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList (
        'LDAP://{0}' -f ([adsi]'LDAP://rootDSE').Properties['schemaNamingContext'].Value
    )
    $schemaVersion = $schema.Properties['objectVersion'].Value

    $return = @{
        schemaVersion = $schemaVersion
        details       = $schemaVersions[$schemaVersion]
    }
    $return
}


function Get-mdiDomainControllerReadiness {

    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)] [string] $Domain
    )

    Write-Verbose -Message "Searching for Domain Controllers in $Domain"
    $dcs = @(Get-ADDomainController -Server $Domain -Filter * | ForEach-Object {
            @{
                FQDN = $_.Hostname
                IP   = $_.IPv4Address
                OS   = $_.OperatingSystem
            }
        })
    Write-Verbose -Message "Found $($dcs.Count) Domain Controller(s)"

    foreach ($dc in $dcs) {


        if (Test-Connection -ComputerName $dc.FQDN -Count 2 -Quiet) {
            $details = [ordered]@{}

            Write-Verbose -Message "Testing server requirements for $($dc.FQDN)"
            $serverRequirements = Get-mdiServerRequirements -ComputerName $dc.FQDN
            $dc.Add('ServerRequirements', $serverRequirements.isMinHwRequirementsOk)
            $details.Add('ServerRequirementsDetails', $serverRequirements.details)

            Write-Verbose -Message "Testing power settings for $($dc.FQDN)"
            $powerSettings = Get-mdiPowerScheme -ComputerName $dc.FQDN
            $dc.Add('PowerSettings', $powerSettings.isPowerSchemeOk)
            $details.Add('PowerSettingsDetails', $powerSettings.details)

            Write-Verbose -Message "Testing advanced auditing for $($dc.FQDN)"
            $advancedAuditing = Get-mdiAdvancedAuditing -ComputerName $dc.FQDN
            $dc.Add('AdvancedAuditing', $advancedAuditing.isAdvancedAuditingOk)
            $details.Add('AdvancedAuditingDetails', $advancedAuditing.details)

            Write-Verbose -Message "Testing NTLM auditing for $($dc.FQDN)"
            $ntlmAuditing = Get-mdiNtlmAuditing -ComputerName $dc.FQDN
            $dc.Add('NtlmAuditing', $ntlmAuditing.isNtlmAuditingOk)
            $details.Add('NtlmAuditingDetails', $ntlmAuditing.details)

            Write-Verbose -Message "Testing certificates readiness for $($dc.FQDN)"
            $certificates = Get-mdiCertReadiness -ComputerName $dc.FQDN
            $dc.Add('RootCertificates', $certificates.isRootCertificatesOk)
            $details.Add('RootCertificatesDetails', $certificates.details)

            Write-Verbose -Message "Testing MDI sensor for $($dc.FQDN)"
            $sensorVersion = Get-mdiSensorVersion -ComputerName $dc.FQDN
            $dc.Add('SensorVersion', $sensorVersion)

            Write-Verbose -Message "Testing capturing component for $($dc.FQDN)"
            $capComponent = Get-mdiCaptureComponent -ComputerName $dc.FQDN
            $dc.Add('CapturingComponent', $capComponent)

            Write-Verbose -Message "Getting virtualization platform for $($dc.FQDN)"
            $machineType = Get-mdiMachineType -ComputerName $dc.FQDN
            $dc.Add('MachineType', $machineType)

            Write-Verbose -Message "Getting Operating System for $($dc.FQDN)"
            $osVer = Get-mdiOSVersion -ComputerName $dc.FQDN
            $dc.Add('OSVersion', $osVer.isOsVerOk)
            $details.Add('OSVersionDetails', $osVer.details)


        } else {
            $dc.Add('Comment', 'Server is not available')
            Write-Warning ('{0} is not available' -f $dc.FQDN)
        }

        $dc.Add('Details', $details)
        [pscustomobject]$dc
    }

}


function Set-MdiReadinessReport {
    param (
        [Parameter(Mandatory = $true)] [string] $Domain,
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [object[]] $ReportData
    )

    $jsonReportFile = Join-Path -Path $Path -ChildPath "mdi-$Domain.json"
    Write-Verbose "Creating detailed json report: $jsonReportFile"
    $ReportData | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonReportFile -Force
    $jsonReportFilePath = (Resolve-Path -Path $jsonReportFile).Path

    $css = @'
<style>
body { font-family: Arial, sans-serif, 'Open Sans'; }
table { border-collapse: collapse; }
td, th { border: 1px solid #aeb0b5; padding: 5px; text-align: center; vertical-align: middle; }
tr:nth-child(even) { background-color: #f2f2f2; }
th { padding: 8px; text-align: left; background-color: #e4e2e0; color: #212121; }
.red    {background-color: #cd2026; color: #ffffff; }
.green  {background-color: #4aa564; color: #212121; }
ul { list-style: none; padding-left: 0.5em;}
li:before { content: "►"; display: block; float: left; width: 1.5em; color: #cd2026; }
</style>
'@
    $properties = [collections.arraylist] @($ReportData.DomainControllers | Get-Member -MemberType NoteProperty |
            Where-Object { $_.Definition -match '(^System.Boolean|^bool)\s+' }).Name
    $properties.Insert(0, 'FQDN')
    $propsToAdd = @('SensorVersion', 'CapturingComponent', 'MachineType', 'Comment')
    [void] $properties.AddRange($propsToAdd)
    $regReplacePattern = '<th>(?!FQDN)(?!{0})(\w+)' -f ($propsToAdd -join '|')
    $htmlDCs = ((($ReportData.DomainControllers | Sort-Object FQDN | Select-Object $properties | ConvertTo-Html -Fragment) `
                -replace $regReplacePattern, '<th><a href="https://aka.ms/mdi/$1">$1</a>') `
            -replace '<td>True', '<td class="green">True') `
        -replace '<td>False', '<td class="red">False' `
        -join [environment]::NewLine


    $htmlDS = ((($ReportData | Select-Object @{N = 'Domain'; E = { $Domain } },
                @{N = 'ObjectAuditing'; E = { $_.DomainObjectAuditing.isObjectAuditingOk } },
                @{N = 'ExchangeAuditing'; E = { $_.DomainExchangeAuditing.isExchangeAuditingOk } },
                @{N = 'AdfsAuditing'; E = { $_.DomainAdfsAuditing.isAdfsAuditingOk } }  | ConvertTo-Html -Fragment) `
                -replace '<th>(?!Domain)(\w+)', '<th><a href="https://aka.ms/mdi/$1">$1</a>') `
            -replace '<td>True', '<td class="green">True') `
        -replace '<td>False', '<td class="red">False' `
        -join [environment]::NewLine

    $htmlContent = @'
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>{0}</head><body>
<h2>MDI readiness report for <b>{1}</b></h2>
<h4>Domain Services readiness</h4>
{2}
<h4>Domain Controllers readiness</h4>
{3}
<h4>Other requirements</h4>
<ul>
<li>For VMware virtualized machines, please verify that the memory is allocated to the virtual machine at all times, and that the <i>'Large Send Offload (LSO)'</i> is disabled</li>
<li>Please verify that the required ports are opened from the sensor servers to the devices on the network. For more details, see <a href='{4}/NNR'>{4}/NNR</a></li>
<li>Please verify that the <i>'Restrict clients allowed to make remote calls to SAM'</i> policy is configured as required. For more details, see <a href='{4}/SAMR'>{4}/SAMR</a></li>
<li>Please verify that the Directory Services Account (DSA) configured for the domain, has read permissions on the <i>Deleted Objects Container</i>. For more details, see <a href='{4}/dsa-permissions'>{4}/dsa-permissions</a></li>
</ul>
<hr>
<br/>Full details file can be found at <a href='{5}'>{5}</a><br/>
<br/>Created at {6} by <a href='{4}/Test-MdiReadiness'>Test-MdiReadiness.ps1</a>
'@ -f $css, $domain, $htmlDS, $htmlDCs, 'https://aka.ms/mdi', $jsonReportFilePath, [datetime]::Now

    $htmlReportFile = Join-Path -Path $Path -ChildPath "mdi-$Domain.html"
    Write-Verbose "Creating html report: $htmlReportFile"
    $htmlContent | Out-File -FilePath $htmlReportFile -Force
    (Resolve-Path -Path $htmlReportFile).Path
}


function Test-mdiReadinessResult {
    param (
        [Parameter(Mandatory = $true)] [object[]] $ReportData
    )
    $properties = @($ReportData.DomainControllers | Get-Member -MemberType NoteProperty |
            Where-Object { $_.Definition -match '^bool' }).Name

    $dcsOk = (($ReportData.DomainControllers | ForEach-Object {
                $dc = $_; $properties | ForEach-Object {
                    $dc | Select-Object -ExpandProperty $_ -ErrorAction SilentlyContinue
                }
            }) -ne $true).Count -eq 0

    $return = $dcsOk -and
        $report.DomainAdfsAuditing.isAdfsAuditingOk -and
            $report.DomainObjectAuditing.isObjectAuditingOk -and
                $report.DomainExchangeAuditing.isExchangeAuditingOk

    $return
}
#endregion


#region Main

if (-not $Domain) { $Domain = $env:USERDNSDOMAIN }
if ($PSCmdlet.ShouldProcess($Domain, 'Create MDI related configuration reports')) {
    $report = @{
        Domain                 = $Domain
        DomainControllers      = Get-mdiDomainControllerReadiness -Domain $Domain
        DomainAdfsAuditing     = Get-mdiAdfsAuditing -Domain $Domain
        DomainObjectAuditing   = Get-mdiObjectAuditing -Domain $Domain
        DomainExchangeAuditing = Get-mdiExchangeAuditing -Domain $Domain
        DomainSchemaVersion    = Get-DomainSchemaVersion -Domain $Domain
    }

    $htmlReportFile = Set-MdiReadinessReport -Domain $Domain -Path $Path -ReportData $report

    Test-mdiReadinessResult -ReportData $report

    if ($OpenHtmlReport) { Invoke-Item -Path $htmlReportFile }
}

#endregion