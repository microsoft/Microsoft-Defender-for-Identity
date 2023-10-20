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
        Path to a folder where the reports are be saved. Defaults to the current folder.
    .PARAMETER Domain
        Domain Name or FQDN to work against. Defaults to the current domain.
    .PARAMETER DomainController
        Specific Domain Controller(s) to work against. If not specified, it will query AD for the list of DCs in the domain.
    .PARAMETER CAServer
        Specific Certificate Authority server(s) to work against. If not specified, it will query AD for the members of the "Cert Publishers" group.
    .PARAMETER SkipCA
        Skip Certificate Authority servers
    .PARAMETER OpenHtmlReport
        Open the HTML report at the end of the collection process.
    .EXAMPLE
        .\Test-MdiReadiness.ps1 -OpenHtmlReport
    .EXAMPLE
        .\Test-MdiReadiness.ps1 -DomainController 'myDC01', 'myDC02'
    .EXAMPLE
        .\Test-MdiReadiness.ps1 -CAServer 'myCA01', 'myCA02'
    .EXAMPLE
        .\Test-MdiReadiness.ps1 -SkipCA
    .EXAMPLE
        .\Test-MdiReadiness.ps1 -Verbose
#>

#Requires -Version 4.0
#requires -Module ActiveDirectory

[CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'IncludeCA')]
param (
    [Parameter(Mandatory = $false, HelpMessage = 'Path to a folder where the reports are be saved')]
    [string] $Path = '.',
    [Parameter(Mandatory = $false, HelpMessage = 'Domain Name or FQDN to work against. Defaults to current domain')]
    [string] $Domain = $null,
    [Parameter(Mandatory = $false, HelpMessage = 'Specific Domain Controller(s) to work against. If not specified, it will query AD for the list of DCs in the domain')]
    [string[]] [Alias('DC')] $DomainController = $null,
    [Parameter(Mandatory = $false, ParameterSetName = 'IncludeCA', HelpMessage = 'Specific Certificate Authority server(s) to work against. If not specified, it will query AD for the members of the "Cert Publishers" group')]
    [string[]] [Alias('CA')] $CAServer = $null,
    [Parameter(Mandatory = $false, ParameterSetName = 'SkipCA', HelpMessage = 'Skip Certificate Authority servers')]
    [switch] $SkipCA,
    [Parameter(Mandatory = $false, HelpMessage = 'Open the HTML report at the end of the collection process')]
    [switch] $OpenHtmlReport
)

#region General settings

$settings = @{

    AdvancedAuditPolicyDCs = @'
Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Setting Value
System,Security System Extension,{0CCE9211-69AE-11D9-BED3-505054503030},Success and Failure,3
System,Distribution Group Management,{0CCE9238-69AE-11D9-BED3-505054503030},Success and Failure,3
System,Security Group Management,{0CCE9237-69AE-11D9-BED3-505054503030},Success and Failure,3
System,Computer Account Management,{0CCE9236-69AE-11D9-BED3-505054503030},Success and Failure,3
System,User Account Management,{0CCE9235-69AE-11D9-BED3-505054503030},Success and Failure,3
System,Directory Service Access,{0CCE923B-69AE-11D9-BED3-505054503030},Success and Failure,3
System,Directory Service Changes,{0CCE923C-69AE-11D9-BED3-505054503030},Success and Failure,3
System,Credential Validation,{0CCE923F-69AE-11D9-BED3-505054503030},Success and Failure,3
'@

    AdvancedAuditPolicyCAs = @'
Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Setting Value
System,Audit Certification Services,{0cce9221-69ae-11d9-bed3-505054503030},Success and Failure,3
'@

    ObjectAuditing         = @'
SecurityIdentifier,AccessMask,AuditFlagsValue,InheritedObjectAceType,Description
S-1-1-0,852331,1,bf967aba-0de6-11d0-a285-00aa003049e2,Descendant User Objects
S-1-1-0,852331,1,bf967a9c-0de6-11d0-a285-00aa003049e2,Descendant Group Objects
S-1-1-0,852331,1,bf967a86-0de6-11d0-a285-00aa003049e2,Descendant Computer Objects
S-1-1-0,852331,1,ce206244-5827-4a86-ba1c-1c0c386c1b64,Descendant msDS-ManagedServiceAccount Objects
S-1-1-0,852075,1,7b8b558a-93a5-4af7-adca-c017e67f1057,Descendant msDS-GroupManagedServiceAccount Objects
'@

    ExchangeAuditing       = @'
SecurityIdentifier,AccessMask,AuditFlagsValue,AceFlagsValue
S-1-1-0,32,3,194
'@

    ADFSAuditing           = @'
SecurityIdentifier,AccessMask,AuditFlagsValue,AceFlagsValue
S-1-1-0,48,3,194
'@

    NTLMAuditing           = @(
        'System\CurrentControlSet\Control\Lsa\MSV1_0,AuditReceivingNTLMTraffic,2',
        'System\CurrentControlSet\Control\Lsa\MSV1_0,RestrictSendingNTLMTraffic,1|2',
        'System\CurrentControlSet\Services\Netlogon\Parameters,AuditNTLMInDomain,7'
    )

    RootCertificates       = @(
        'D4DE20D05E66FC53FE1A50882C78DB2852CAE474'   # All customers, Baltimore CyberTrust Root
        , 'DF3C24F9BFD666761B268073FE06D1CC8D4F82A4' # Commercial, DigiCert Global Root G2
        , 'A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436' # USGov, DigiCert Global Root CA
    )

    CASettings             = @{
        RegPathActive = 'System\CurrentControlSet\Services\CertSvc\Configuration,Active'
        RegistrySet   = @(
            'System\CurrentControlSet\Services\CertSvc\Configuration\{0},AuditFilter,127'
        )
    }
}

#endregion

#region Helper functions

function Get-mdiRemoteTempFolder {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName
    )

    try {
        $wmiParamsTemp = @{
            ComputerName = $ComputerName
            Namespace    = 'root\cimv2'
            Class        = 'Win32_Environment'
            Filter       = "Name='TEMP' AND SystemVariable=TRUE"
            ErrorAction  = 'SilentlyContinue'
        }
        $envTempPath = (Get-WmiObject @wmiParamsTemp).VariableValue

        if ($envTempPath -match '%SystemDrive%|%SystemDirectory%|%WindowsDirectory%') {
            $wmiParamsOS = @{
                ComputerName = $ComputerName
                Namespace    = 'root\cimv2'
                Class        = 'Win32_OperatingSystem'
                ErrorAction  = 'SilentlyContinue'
            }
            $osVars = Get-WmiObject @wmiParamsOS
            $envTempPath = $envTempPath -replace '%SystemDrive%', $osVars.SystemDrive
            $envTempPath = $envTempPath -replace '%SystemDirectory%', $osVars.SystemDirectory
            $envTempPath = $envTempPath -replace '%WindowsDirectory%', $osVars.WindowsDirectory
        }

        if ($envTempPath -match '%SystemRoot%') {
            $HKLM = 2147483650
            $reg = [WMIClass]('\\{0}\ROOT\DEFAULT:StdRegProv' -f $ComputerName)
            $SystemRoot = $reg.GetStringValue($HKLM, 'SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'SystemRoot').sValue
            $envTempPath = $envTempPath -replace '%SystemRoot%', $SystemRoot
        }

    } catch {
        $envTempPath = 'C:\Windows\Temp'
    }
    $envTempPath
}

function Invoke-mdiRemoteCommand {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName,
        [Parameter(Mandatory = $true)] [string] $CommandLine,
        [Parameter(Mandatory = $false)] [string] $LocalFile = $null
    )

    try {
        $wmiParams = @{
            ComputerName = $ComputerName
            Namespace    = 'root\cimv2'
            Class        = 'Win32_Process'
            Name         = 'Create'
            ErrorAction  = 'SilentlyContinue'
        }
        if ($LocalFile -eq [string]::Empty) {
            $LocalFile = Join-Path -Path (Get-mdiRemoteTempFolder -ComputerName $ComputerName) -ChildPath ('mdi-{0}.tmp' -f , [guid]::NewGuid().GUID)
            $wmiParams['ArgumentList'] = '{0} 2>&1>{1}' -f $CommandLine, $LocalFile
        } else {
            $wmiParams['ArgumentList'] = $CommandLine
        }

        $result = Invoke-WmiMethod @wmiParams
        $maxWait = [datetime]::Now.AddSeconds(30)

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
    } catch {
        $return = $_.Exception.Message
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
        $return = [PSCustomObject]@{
            isPowerSchemeOk = $Matches.guid -eq '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'
            details         = $details
        }
    } else {
        $return = [PSCustomObject]@{
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
    try {
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

        $minRequirements = @{
            NumberOfLogicalProcessors = 2
            TotalPhysicalMemory       = 6gb - 1mb
            OsDiskFreeSpace           = 6gb
        }
        $return = [PSCustomObject]@{
            isMinHwRequirementsOk = (
                $csi.NumberOfLogicalProcessors -ge $minRequirements.NumberOfLogicalProcessors -and
                $csi.TotalPhysicalMemory -ge $minRequirements.TotalPhysicalMemory -and
                $osdisk.FreeSpace -ge $minRequirements.OsDiskFreeSpace
            )
            details               = [PSCustomObject]@{
                NumberOfLogicalProcessors = $csi.NumberOfLogicalProcessors
                TotalPhysicalMemory       = $csi.TotalPhysicalMemory
                OsDiskDeviceID            = $osdisk.DeviceID
                OsDiskFreeSpace           = $osdisk.FreeSpace
            }
        }
    } catch {
        $return = [PSCustomObject]@{
            isMinHwRequirementsOk = $false
            details               = $_.Exception.Message
        }
    }
    $return
}

function Get-mdiRegistryValueSet {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName,
        [Parameter(Mandatory = $true)] [string[]] $ExpectedRegistrySet
    )

    $hklm = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName, 'Registry64')
    $details = foreach ($reg in $ExpectedRegistrySet) {

        $regKeyPath, $regValue, $expectedValue = $reg -split ','
        $regKey = $hklm.OpenSubKey($regKeyPath)
        $value = $regKey.GetValue($regValue)

        [PSCustomObject]@{
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

    $details = Get-mdiRegistryValueSet -ComputerName $ComputerName -ExpectedRegistrySet $settings.NTLMAuditing
    [PSCustomObject]@{
        isNtlmAuditingOk = @($details | Where-Object { $_.value -notmatch $_.expectedValue }).Count -eq 0
        details          = $details | Select-Object regKey, value
    }
}

function Get-mdiCAAuditing {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName
    )

    $activeName = Get-mdiRegistryValueSet -ComputerName $ComputerName -ExpectedRegistrySet $settings.CASettings.RegPathActive
    $details = $settings.CASettings.RegistrySet | ForEach-Object {
        Get-mdiRegistryValueSet -ComputerName $ComputerName -ExpectedRegistrySet ($_ -f $activeName.value)
    }
    [PSCustomObject]@{
        isCaAuditingOk = @($details | Where-Object { $_.value -notmatch $_.expectedValue }).Count -eq 0
        details        = $details | Select-Object regKey, value
    }
}

function Get-mdiCertReadiness {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName
    )

    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("\\$ComputerName\Root",
        [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    $details = $store.Certificates | Where-Object { $settings.RootCertificates -contains $_.Thumbprint }
    $store.Close()
    [PSCustomObject]@{
        isRootCertificatesOk = @($details).Count -gt 1
        details              = $details | Select-Object -Property Thumbprint, Subject, Issuer, NotBefore, NotAfter
    }
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
        $return = $_.Exception.Message
    }
    $return
}

function Get-mdiMachineType {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName
    )
    try {
        $csiParams = @{
            ComputerName = $ComputerName
            Namespace    = 'root\cimv2'
            Class        = 'Win32_ComputerSystem'
            Property     = 'Model', 'Manufacturer'
            ErrorAction  = 'SilentlyContinue'
        }
        $csi = Get-WmiObject @csiParams
        $return = switch ($csi.Model) {
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
    } catch {
        $return = $_.Exception.Message
    }
    $return
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
        $return = [PSCustomObject]@{
            isOsVerOk = [version]($os.Version) -ge [version]('6.3')
            details   = [PSCustomObject]@{
                Caption = $os.Caption
                Version = $os.Version
            }
        }
    } catch {
        $return = [PSCustomObject]@{
            isOsVerOk = $false
            details   = [PSCustomObject]@{
                Caption = 'N/A'
                Version = 'N/A'
            }
        }
    }
    $return
}

function Get-mdiAdvancedAuditing {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName,
        [Parameter(Mandatory = $true)] [string[]] $ExpectedAuditing
    )
    $properties = 'Policy Target', 'Subcategory GUID', 'Inclusion Setting', 'Setting Value'
    $expected = @($ExpectedAuditing | ConvertFrom-Csv)
    $LocalFile = Join-Path -Path (Get-mdiRemoteTempFolder -ComputerName $ComputerName) -ChildPath ('mdi-{0}.csv' -f , [guid]::NewGuid().GUID)
    $commandLine = 'cmd.exe /c auditpol.exe /backup /file:{0}' -f $LocalFile
    $output = Invoke-mdiRemoteCommand -ComputerName $ComputerName -CommandLine $commandLine -LocalFile $LocalFile
    if ($output -and $output.Count -gt 1) {
        $actual = $output | ConvertFrom-Csv | Where-Object {
            $_.'Subcategory GUID' -in $expected.'Subcategory GUID'
        } | Select-Object -Property $properties

        $compareParams = @{
            ReferenceObject  = $expected
            DifferenceObject = $actual
            Property         = $properties
        }
        $isAdvancedAuditingOk = $null -eq (Compare-Object @compareParams)
        $return = [PSCustomObject]@{
            isAdvancedAuditingOk = $isAdvancedAuditingOk
            details              = $actual
        }
    } else {
        $return = [PSCustomObject]@{
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

        $return = [PSCustomObject]@{
            isAuditingOk = @(Compare-Object @compareParams -ExcludeDifferent -IncludeEqual).Count -eq $expectedAuditing.Count
            details      = $appliedAuditing
        }
    } catch {
        $e = $_
        $return = [PSCustomObject]@{
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
    $expectedAuditing = $settings.ObjectAuditing | ConvertFrom-Csv | Select-Object SecurityIdentifier, AccessMask, AuditFlagsValue, InheritedObjectAceType

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

    $expectedAuditing = $settings.ExchangeAuditing | ConvertFrom-Csv

    $ds = [adsi]('LDAP://{0}/ROOTDSE' -f $Domain)

    $exchangePath = 'LDAP://CN=Microsoft Exchange,CN=Services,CN=Configuration,{0}' -f $ds.defaultNamingContext.Value
    if ([System.DirectoryServices.DirectoryEntry]::Exists($exchangePath)) {

        $ldapPath = 'LDAP://CN=Configuration,{0}' -f $ds.defaultNamingContext.Value

        $result = Get-mdiDsSacl -LdapPath $ldapPath -ExpectedAuditing $expectedAuditing

        if ($result.isAuditingOk -eq 'N/A') {
            $isAuditingOk = $result.isAuditingOk
        } else {
            $appliedAuditing = $result.details
            $isAuditingOk = @(foreach ($applied in $appliedAuditing) {
                    $expectedAuditing | Where-Object { ($_.SecurityIdentifier -eq $applied.SecurityIdentifier) -and ($_.AuditFlagsValue -eq $applied.AuditFlagsValue) -and
                ($_.InheritedObjectAceType -eq $applied.InheritedObjectAceType) -and
                    (([System.DirectoryServices.ActiveDirectoryRights]$applied.AccessMask).HasFlag(([System.DirectoryServices.ActiveDirectoryRights]($_.AccessMask)))) }
                }).Count -eq @($expectedAuditing).Count
        }
        $return = @{
            isExchangeAuditingOk = $isAuditingOk
            details              = $result.details
        }
    } else {
        $return = @{
            isExchangeAuditingOk = 'N/A'
            details              = 'Microsoft Exchange Services Configuration container not found'
        }
    }
    $return
}

function Get-mdiAdfsAuditing {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)] [string] $Domain
    )

    Write-Verbose -Message 'Getting MDI related ADFS auditing configuration'

    $expectedAuditing = $settings.ADFSAuditing | ConvertFrom-Csv

    $ds = [adsi]('LDAP://{0}/ROOTDSE' -f $Domain)
    $ldapPath = 'LDAP://CN=ADFS,CN=Microsoft,CN=Program Data,{0}' -f $ds.defaultNamingContext.Value

    $result = Get-mdiDsSacl -LdapPath $ldapPath -ExpectedAuditing $expectedAuditing

    if ($result.isAuditingOk -ne 'N/A') {
        $appliedAuditing = $result.details
        $isAuditingOk = @(foreach ($applied in $appliedAuditing) {
                $expectedAuditing | Where-Object { ($_.SecurityIdentifier -eq $applied.SecurityIdentifier) -and ($_.AuditFlagsValue -eq $applied.AuditFlagsValue) -and
            ($_.InheritedObjectAceType -eq $applied.InheritedObjectAceType) -and
                (([System.DirectoryServices.ActiveDirectoryRights]$applied.AccessMask).HasFlag(([System.DirectoryServices.ActiveDirectoryRights]($_.AccessMask)))) }
            }).Count -eq @($expectedAuditing).Count
        $return = @{
            isAdfsAuditingOk = $isAuditingOk
            details          = $result.details
        }
    } else {
        $return = @{
            isAdfsAuditingOk = $result.isAuditingOk
            details          = 'Microsoft ADFS Program Data container not found'
        }
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
        90 = 'Windows Server vNext'
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
        [Parameter(Mandatory = $true)] [string] $Domain,
        [Parameter(Mandatory = $false)] [string[]] $DomainController = $null
    )

    if ([string]::IsNullOrEmpty($DomainController)) {
        Write-Verbose -Message "Searching for Domain Controllers in $Domain"
        try {
            $DomainController = @(Get-ADDomainController -Server $Domain -Filter * -ErrorAction Stop | Select-Object -ExpandProperty Name)
        } catch {
            $DomainController = $null
        }
    } else {
        Write-Verbose -Message "Using the provided list of Domain Controller(s)"
    }
    $dcs = @($DomainController | ForEach-Object {
            try {
                $dcComputer = Get-ADComputer -Identity $_ -Server $Domain -Properties DNSHostName, IPv4Address, OperatingSystem -ErrorAction SilentlyContinue
                @{
                    FQDN = $dcComputer.DNSHostName
                    IP   = $dcComputer.IPv4Address
                    OS   = $dcComputer.OperatingSystem
                }
            } catch {
                Write-Verbose $_.Exception.Message
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
            $advancedAuditing = Get-mdiAdvancedAuditing -ComputerName $dc.FQDN -ExpectedAuditing $settings.AdvancedAuditPolicyDCs
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
        [PSCustomObject]$dc
    }
}

function Get-mdiCAReadiness {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)] [string] $Domain,
        [Parameter(Mandatory = $false)] [string[]] $CAServer = $null
    )

    if ([string]::IsNullOrEmpty($CAServer)) {
        Write-Verbose -Message "Searching for CA servers in $Domain"
        try {
            $CAServer = Get-ADGroupMember -Server $Domain -Identity 'Cert Publishers' -ErrorAction Stop | Where-Object { $_.objectClass -eq 'computer' }
        } catch {
            $CAServer = $null
        }
    } else {
        Write-Verbose -Message "Using the provided list of CA server(s)"
    }
    $cas = @($CAServer | ForEach-Object {
            try {
                $caComputer = Get-ADComputer -Identity $_ -Server $Domain -Properties DNSHostName, IPv4Address, OperatingSystem -ErrorAction SilentlyContinue
                @{
                    FQDN = $caComputer.DNSHostName
                    IP   = $caComputer.IPv4Address
                    OS   = $caComputer.OperatingSystem
                }
            } catch {
                Write-Verbose $_.Exception.Message
            }
        })
    Write-Verbose -Message "Found $($cas.Count) CA server(s)"

    foreach ($ca in $cas) {

        if (Test-Connection -ComputerName $ca.FQDN -Count 2 -Quiet) {
            $details = [ordered]@{}

            Write-Verbose -Message "Testing server requirements for $($ca.FQDN)"
            $serverRequirements = Get-mdiServerRequirements -ComputerName $ca.FQDN
            $ca.Add('ServerRequirements', $serverRequirements.isMinHwRequirementsOk)
            $details.Add('ServerRequirementsDetails', $serverRequirements.details)

            Write-Verbose -Message "Testing power settings for $($ca.FQDN)"
            $powerSettings = Get-mdiPowerScheme -ComputerName $ca.FQDN
            $ca.Add('PowerSettings', $powerSettings.isPowerSchemeOk)
            $details.Add('PowerSettingsDetails', $powerSettings.details)

            Write-Verbose -Message "Testing advanced auditing for $($ca.FQDN)"
            $advancedAuditingCA = Get-mdiAdvancedAuditing -ComputerName $ca.FQDN -ExpectedAuditing $settings.AdvancedAuditPolicyCAs
            $ca.Add('AdvancedAuditingCA', $advancedAuditingCA.isAdvancedAuditingOk)
            $details.Add('AdvancedAuditingCADetails', $advancedAuditingCA.details)

            Write-Verbose -Message "Testing CA auditing for $($ca.FQDN)"
            $caAuditing = Get-mdiCAAuditing -ComputerName $ca.FQDN
            $ca.Add('CAAuditing', $caAuditing.isCaAuditingOk)
            $details.Add('CAAuditingDetails', $caAuditing.details)

            Write-Verbose -Message "Testing certificates readiness for $($ca.FQDN)"
            $certificates = Get-mdiCertReadiness -ComputerName $ca.FQDN
            $ca.Add('RootCertificates', $certificates.isRootCertificatesOk)
            $details.Add('RootCertificatesDetails', $certificates.details)

            Write-Verbose -Message "Testing MDI sensor for $($ca.FQDN)"
            $sensorVersion = Get-mdiSensorVersion -ComputerName $ca.FQDN
            $ca.Add('SensorVersion', $sensorVersion)

            Write-Verbose -Message "Testing capturing component for $($ca.FQDN)"
            $capComponent = Get-mdiCaptureComponent -ComputerName $ca.FQDN
            $ca.Add('CapturingComponent', $capComponent)

            Write-Verbose -Message "Getting virtualization platform for $($ca.FQDN)"
            $machineType = Get-mdiMachineType -ComputerName $ca.FQDN
            $ca.Add('MachineType', $machineType)

            Write-Verbose -Message "Getting Operating System for $($ca.FQDN)"
            $osVer = Get-mdiOSVersion -ComputerName $ca.FQDN
            $ca.Add('OSVersion', $osVer.isOsVerOk)
            $details.Add('OSVersionDetails', $osVer.details)


        } else {
            $ca.Add('Comment', 'Server is not available')
            Write-Warning ('{0} is not available' -f $ca.FQDN)
        }

        $ca.Add('Details', $details)
        [PSCustomObject]$ca
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

    $htmlCAs = if ($ReportData.CAServers) {
        $properties = [collections.arraylist] @($ReportData.CAServers | Get-Member -MemberType NoteProperty |
                Where-Object { $_.Definition -match '(^System.Boolean|^bool)\s+' }).Name
        if ($null -ne $properties) {
            $properties.Insert(0, 'FQDN')
            $propsToAdd = @('SensorVersion', 'CapturingComponent', 'MachineType', 'Comment')
            [void] $properties.AddRange($propsToAdd)
        } else {
            $properties = [collections.arraylist]@('FQDN', 'Comment')
        }
        $regReplacePattern = '<th>(?!FQDN)(?!{0})(\w+)' -f ($propsToAdd -join '|')
        ((($ReportData.CAServers | Sort-Object FQDN | Select-Object $properties | ConvertTo-Html -Fragment) `
                -replace $regReplacePattern, '<th><a href="https://aka.ms/mdi/$1">$1</a>') `
            -replace '<td>True', '<td class="green">True') `
            -replace '<td>False', '<td class="red">False' `
            -join [environment]::NewLine
    } elseif ($SkipCA) {
        '<table><tr><td>CA servers validation skipped</td></tr></table>'
    } else {
        '<table><tr><td>No CA servers found</td></tr></table>'
    }

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
<h4>CA servers readiness</h4>
{4}
<h4>Other requirements</h4>
<ul>
<li>For VMware virtualized machines, please verify that the memory is allocated to the virtual machine at all times, and that the <i>'Large Send Offload (LSO)'</i> is disabled</li>
<li>Please verify that the required ports are opened from the sensor servers to the devices on the network. For more details, see <a href='{5}/NNR'>{5}/NNR</a></li>
<li>Please verify that the <i>'Restrict clients allowed to make remote calls to SAM'</i> policy is configured as required. For more details, see <a href='{5}/SAMR'>{5}/SAMR</a></li>
<li>Please verify that the Directory Services Account (DSA) configured for the domain, has read permissions on the <i>Deleted Objects Container</i>. For more details, see <a href='{5}/dsa-permissions'>{5}/dsa-permissions</a></li>
</ul>
<hr>
<br/>Full details file can be found at <a href='{6}'>{6}</a><br/>
<br/>Created at {7} by <a href='{5}/Test-MdiReadiness'>Test-MdiReadiness.ps1</a>
'@ -f $css, $domain, $htmlDS, $htmlDCs, $htmlCAs, 'https://aka.ms/mdi', $jsonReportFilePath, [datetime]::Now

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

    $casOk = (($ReportData.CAServers | ForEach-Object {
                $ca = $_; $properties | ForEach-Object {
                    $ca | Select-Object -ExpandProperty $_ -ErrorAction SilentlyContinue
                }
            }) -ne $true).Count -eq 0

    $return = $dcsOk -and $casOk -and
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
        DomainControllers      = Get-mdiDomainControllerReadiness -Domain $Domain -DomainController $DomainController
        DomainAdfsAuditing     = Get-mdiAdfsAuditing -Domain $Domain
        DomainObjectAuditing   = Get-mdiObjectAuditing -Domain $Domain
        DomainExchangeAuditing = Get-mdiExchangeAuditing -Domain $Domain
        DomainSchemaVersion    = Get-DomainSchemaVersion -Domain $Domain
    }
    if (-not $SkipCA) {
        $report.CAServers = Get-mdiCAReadiness -Domain $Domain -CAServer $CAServer
    }

    $htmlReportFile = Set-MdiReadinessReport -Domain $Domain -Path $Path -ReportData $report

    Test-mdiReadinessResult -ReportData $report

    if ($OpenHtmlReport) { Invoke-Item -Path $htmlReportFile }
}

#endregion
