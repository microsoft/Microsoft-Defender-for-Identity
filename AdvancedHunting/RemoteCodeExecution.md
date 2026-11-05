# Detect potential remote code execution (RCE) activity via WMI, scheduled tasks, and service creation

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title | Link |
| --- | --- | --- |
| T1047 | Windows Management Instrumentation | https://attack.mitre.org/techniques/T1047/ |
| T1053.005 | Scheduled Task/Job: Scheduled Task | https://attack.mitre.org/techniques/T1053/005/ |
| T1543.003 | Create or Modify System Process: Windows Service | https://attack.mitre.org/techniques/T1543/003/ |

#### Description
This query detects suspicious remote execution behavior by monitoring three activity types: WMI execution (`win32_process create`), task scheduling, and service creation.

It applies a historical baseline over the previous 7 days and suppresses entities (account or source device) that performed the same action type on at least 3 distinct days, reducing recurring administrative noise and surfacing anomalous execution patterns.

## Defender XDR
```KQL
///
// Remote Code Execution
//
// Detects:
// - WMI Win32_Process Create
// - Task scheduling
// - Service creation
//
// Suppresses activity when the same account or source device
// has performed the same action type on >= baseline_days
// distinct days during the previous baseline_lookback period.
let end_time = now();
let start_time = end_time - 1d;
let baseline_lookback = 7d;      // Historical baseline period
let baseline_days = 3;           // Suppress if observed on this many or more distinct days
let baseline_start = start_time - baseline_lookback;
// Candidate remote execution activity
let PotentialAlerts = materialize(
    IdentityDirectoryEvents
    | where Timestamp between (start_time .. end_time)
    | where ActionType in ("Task scheduling", "Service creation", "WMI execution")
    | extend AF = parse_json(AdditionalFields)
    | extend
        WmiMethod = tostring(AF.MethodName),
        TaskName = tostring(AF.TaskName),
        ServiceName = tostring(AF.ServiceName),
        ServiceCommand = tostring(AF.ServiceCommand),
        SourceAccountId = tostring(AF.SourceAccountId),
        SourceComputerId = tostring(AF.SourceComputerId),
        RemoteHost = coalesce(
            DestinationDeviceName,
            TargetDeviceName,
            tostring(AF["TO.DEVICE"]),
            tostring(AF["TARGET_OBJECT.DEVICE"])
        ),
        SourceOS = tostring(AF.SourceComputerOperatingSystem),
        DestinationOS = tostring(AF.DestinationComputerOperatingSystem),
        TargetOS = tostring(AF.TargetComputerOperatingSystem)
    | where
        ActionType == "Task scheduling"
        or (
            ActionType == "Service creation"
            and (
                isempty(ServiceCommand)
                or ServiceCommand !contains @"\Windows\System32\svchost.exe -k"
            )
        )
        or (
            ActionType == "WMI execution"
            and WmiMethod has_cs "win32_process"
            and WmiMethod has_cs "create"
        )
);
// Historical activity by account
let AccountBaseline =
    PotentialAlerts
    | where isnotempty(AccountSid)
    | distinct ActionType, AccountSid
    | join kind=inner (
        IdentityDirectoryEvents
        | where Timestamp between (baseline_start .. start_time)
        | summarize AccountActiveDays = dcount(startofday(Timestamp))
            by ActionType, AccountSid
    ) on ActionType, AccountSid;
// Historical activity by source device
let DeviceBaseline =
    PotentialAlerts
    | where isnotempty(SourceComputerId)
    | distinct ActionType, SourceComputerId
    | join kind=inner (
        IdentityDirectoryEvents
        | where Timestamp between (baseline_start .. start_time)
        | extend AF = parse_json(AdditionalFields)
        | extend SourceComputerId = tostring(AF.SourceComputerId)
        | summarize DeviceActiveDays = dcount(startofday(Timestamp))
            by ActionType, SourceComputerId
    ) on ActionType, SourceComputerId;
// Suppress established activity and summarize results
PotentialAlerts
| join kind=leftouter AccountBaseline on ActionType, AccountSid
| join kind=leftouter DeviceBaseline on ActionType, SourceComputerId
| extend
    AccountActiveDays = coalesce(AccountActiveDays, 0),
    DeviceActiveDays = coalesce(DeviceActiveDays, 0)
| where AccountActiveDays < baseline_days
| where DeviceActiveDays < baseline_days
| summarize
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    ReportId = any(ReportId),
    TotalEvents = count(),
    TargetCount = dcount(RemoteHost),
    Targets = make_set(RemoteHost, 100),
    AttackTechniques = make_set_if(tostring(AF.AttackTechniques), isnotempty(tostring(AF.AttackTechniques)), 100),
    WmiMethods = make_set_if(WmiMethod, isnotempty(WmiMethod), 100),
    Tasks = make_set_if(TaskName, isnotempty(TaskName), 100),
    Services = make_set_if(ServiceName, isnotempty(ServiceName), 100),
    ServiceCommands = make_set_if(ServiceCommand, isnotempty(ServiceCommand), 20),
    SourceOSes = make_set_if(SourceOS, isnotempty(SourceOS), 10),
    DestinationOSes = make_set_if(DestinationOS, isnotempty(DestinationOS), 10),
    TargetOSes = make_set_if(TargetOS, isnotempty(TargetOS), 10)
by
    ActionType,
    AccountName,
    AccountDomain,
    AccountSid,
    SourceAccountId,
    DeviceName,
    SourceComputerId,
    IPAddress
| order by TargetCount desc, TotalEvents desc
| project-reorder ActionType, ReportId, FirstSeen, LastSeen
```
