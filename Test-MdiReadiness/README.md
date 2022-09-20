# Test-MdiReadiness.ps1

The Test-MdiReadiness.ps1 script will query your domain and domain controllers to report if the different **Microsoft Defender for Identity** prerequisites are in place or not. It creates an html report and a detailed json file with all the collected data.

It will check the domain for the following items:

- [Object Auditing](https://aka.ms/mdi/objectauditing)
- [Exchange Auditing](https://aka.ms/mdi/exchangeauditing)
- [ADFS Auditing](https://aka.ms/mdi/adfsauditing)

It will test the domain controllers for the following items:

- [Advanced Audit Policy Configuration](https://aka.ms/mdi/advancedauditing)
- [NTLM Auditing](https://aka.ms/mdi/ntlmauditing)
- [Power scheme is set to *high performance*](https://aka.ms/mdi/powersettings)
- [Root certificates are updated](https://aka.ms/mdi/rootcertificates)

![example html report](html-report.png)

```txt
NAME
    .\Test-MdiReadiness.ps1

SYNOPSIS
    Verifies Microsoft Defender for Identity prerequisites are in place

DESCRIPTION
    This script will query your domain and report if the different Microsoft Defender for Identity prerequisites are in place. It creates an html report and a detailed json file with all the collected data.

SYNTAX
    .\Test-MdiReadiness.ps1 [[-Path] <String>] [[-Domain] <String>] [-OpenHtmlReport] [-WhatIf] [-Confirm] [<CommonParameters>]

PARAMETERS
    -Path <String>
        Path to a folder where the reports are be saved

        Required?                    false
        Position?                    1
        Default value                .
        Accept pipeline input?       false
        Accept wildcard characters?  false

    -Domain <String>
        Domain Name or FQDN to work against. Defaults to current domain

        Required?                    false
        Position?                    2
        Default value
        Accept pipeline input?       false
        Accept wildcard characters?  false

    -OpenHtmlReport [<SwitchParameter>]
        Open the HTML report at the end of the collection process

        Required?                    false
        Position?                    named
        Default value                False
        Accept pipeline input?       false
        Accept wildcard characters?  false


NOTES

        Copyright (c) Microsoft Corporation.  All rights reserved.
        Use of this sample source code is subject to the terms of the Microsoft
        license agreement under which you licensed this sample source code. If
        you did not accept the terms of the license agreement, you are not
        authorized to use this sample source code.
        THE SAMPLE SOURCE CODE IS PROVIDED "AS IS", WITH NO WARRANTIES.

    -------------------------- EXAMPLE 1 --------------------------

    PS C:\>.\Test-MdiReadiness.ps1 -OpenHtmlReport
    False

    -------------------------- EXAMPLE 2 --------------------------

    PS C:\>.\Test-MdiReadiness.ps1 -Verbose

    VERBOSE: Performing the operation "Create MDI related configuration reports" on target "CONTOSO.COM".
    VERBOSE: Searching for Domain Controllers in CONTOSO.COM
    VERBOSE: Found 2 Domain Controller(s)
    VERBOSE: Testing power settings for DC1.CONTOSO.COM
    VERBOSE: Testing advanced auditing for DC1.CONTOSO.COM
    VERBOSE: Testing NTLM auditing for DC1.CONTOSO.COM
    VERBOSE: Testing certificates readiness for DC1.CONTOSO.COM
    VERBOSE: Testing power settings for DC2.CONTOSO.COM
    VERBOSE: Testing advanced auditing for DC2.CONTOSO.COM
    VERBOSE: Testing NTLM auditing for DC2.CONTOSO.COM
    VERBOSE: Testing certificates readiness for DC2.CONTOSO.COM
    VERBOSE: Getting MDI related ADFS auditing configuration
    VERBOSE: Getting MDI related DS Object auditing configuration
    VERBOSE: Getting MDI related Exchange auditing configuration
    VERBOSE: Creating detailed json report: .\mdi-CONTOSO.COM.json
    VERBOSE: Creating html report: .\mdi-CONTOSO.COM.html
    False
```
