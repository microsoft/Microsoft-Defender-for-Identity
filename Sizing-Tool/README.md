# Microsoft Defender for Identity Sizing Tool - Version 1.3.0.0

> [!NOTE]
> This sizing tool is relevant only for Microsoft Defender for Identity sensor v2. It does not apply to sensor v3.

[**Click here to download the tool**](https://github.com/microsoft/Microsoft-Defender-for-Identity/releases)

The sizing tool automates collection of the amount of traffic MDI would need to monitor and automatically provides supportability and resource recommendations for both the ATA (Center and Gateway) and MDI (Sensor).
It is recommended that you run the MDI sizing tool as follows:

- With domain admin credentials
- From a domain-joined workstation that has network access to all the domain controllers on the following ports: TCP 135, TCP 389 ,TCP 445 and TCP RPC Dynamic Ports. If these ports are blocked, you may experience an error message "Remote Registry Query Failed" in the OS Server Level field
- Make sure you have .Net 4.5.2 or later installed
- Make sure that the EPPlus dll, that is included in the zip, is in the same folder that the sizing tool is being used from

The sizing tool uses the RPC protocol, specifically Remote WMI and Remote PerfMon over RPC.  When the tool launches, it enumerates all domain controllers in the domain (by default) using LDAP.  Then it contacts each DC and performs an initial remote performance counter query and a couple of WMI queries.  After these queries are done, it uses the remote performance counters to repeatedly ask each DC for certain perf data (CPU, Mem, packets) roughly every 5 seconds (by default) for the duration of its execution. The tool generates an Excel file summarizing its findings and recommendations.

By default, the tool runs for 24 hours (this is the recommended amount of time to run it) and gathers data including the packets/sec counter, operating system version, compute utilization, and memory utilization.

> [!TIP]
> Do not run the tool using an account that is a member of the [Protected Users Group](https://learn.microsoft.com/windows-server/security/credentials-protection-and-management/protected-users-security-group#protections-applied-by-active-directory). It will prevent the user from renewing the Kerberos TGTs beyond the initial four-hour lifetime, and the tool will fail to authenticate to the remote server(s).
>

For guidance on interpreting the results, see [Plan capacity for deployment - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/deploy/capacity-planning#use-the-sizing-tool).

To choose which domain controllers the tool evaluates remotely, use one of the following command line parameters:

| Command line parameters(evaluates remotely) | Evaluation |
| :------------------------------------------ | :----------- |
| `-DomainFQDN=<Domain FQDN>` | Evaluates all the domain controllers in the specified domain. |
| `-InputDCListFile=<File path>` |Evaluates all the domain controllers in the specified file (each domain controller is presented on a separate line). |
| `-UseCurrent=UserDomain` | Evaluates all the domain controllers in the domain of the user running the tool. |
| `-UseCurrent=ComputerDomain` | Evaluates all the domain controllers in the domain of the computer running the tool.|
| `-UseCurrent=Forest` | Evaluates all the domain controllers in the entire forest. |

If none of the above are specified, UseCurrent=UserDomain is used.

For more options, run "TriSizingTool -?"

Verified on the following platforms:

| OS  | Is Verified |
| :------------- | :------------- |
| Windows Server 2025     | Yes |
| Windows Server 2022     | Yes |
| Windows Server 2019     | Yes |
| Windows Server 2016     | Yes |
| Windows Server 2012 R2  | Yes |
| Windows Server 2012     | Yes |
| Windows Server 2008 R2  | Yes |
| Windows Server 2008     | Yes |
| Windows Server 2003     | No  |
| Windows 11    | Yes |
| Windows 10    | Yes |
| Windows 8     | Yes |
| Windows 7     | Yes |
| Windows Vista | No  |
| Windows XP    | No  |
| Windows 2000  | No  |

[**Click here to download the tool**](https://github.com/microsoft/Microsoft-Defender-for-Identity/releases)