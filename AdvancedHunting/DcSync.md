# Detect anomalous Directory Services replication (DCSync) activity

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title | Link |
| --- | --- | --- |
| T1003.006 | OS Credential Dumping: DCSync | https://attack.mitre.org/techniques/T1003/006/ |

#### Description
This query detects potential DCSync attacks by identifying anomalous Directory Services replication requests. It builds a historical baseline over the prior 8 days and excludes actors, devices, and IPs that routinely perform replication (more than 5 syncs, or active on more than 3 days). Known Entra Connect servers, domain controllers, their IPs, and service accounts are allowlisted to reduce false positives, surfacing only unexpected replication sources from the last day.

## Defender XDR
```KQL
// Known Devices Allowlist
let knownEntraServerDevices = dynamic([
  // e.g. "EntraConnect1"
]);
let knownEntraServerIPs = dynamic([
  // e.g. "10.0.0.10"
]);
let knownEntraConnectAccounts = dynamic([
  // e.g. "MSOL_1337"
]);
let knownDcDevices = dynamic([
  // e.g. "DC1"
]);
let KnownDcIps = dynamic([
  // e.g. "10.0.0.10"
]);
// Historical baseline: last 8 days, ending 1 day ago
let historicalData =
    IdentityDirectoryEvents
    | where Timestamp between (ago(8d) .. ago(1d))
    | where ActionType == "Directory Services replication"
    | extend SourceAccountName = tostring(parse_json(AdditionalFields)["ACTOR.ACCOUNT"])
    | project Timestamp, IPAddress, SourceAccountName, DeviceName;
// Historical "noisy" actors/devices/IPs: more than 5 replication syncs in baseline window
let historicalHighSyncers =
    historicalData
    | summarize HistoricalSyncCount = count() by DeviceName, IPAddress, SourceAccountName
    | where HistoricalSyncCount > 5;
let historicalMultiDayActors =
    historicalData
    | extend Day = startofday(Timestamp)
    | summarize HistoricalActiveDays = dcount(Day) by DeviceName, IPAddress, SourceAccountName
    | where HistoricalActiveDays > 3;
// 1 day lookup for sync
IdentityDirectoryEvents
| where ActionType == "Directory Services replication"
| extend SourceAccountName = tostring(parse_json(AdditionalFields)["ACTOR.ACCOUNT"])
| where isnotempty(SourceAccountName)
| where DeviceName !in (knownEntraServerDevices) and DeviceName !in(knownDcDevices)
| where IPAddress !in (knownEntraServerIPs) and IPAddress !in (KnownDcIps)
| where SourceAccountName !in (knownEntraConnectAccounts)
// Remove anything that historically performed >5 replication syncs
| join kind=leftanti (historicalHighSyncers) on DeviceName, IPAddress, SourceAccountName
| join kind=leftanti (historicalMultiDayActors) on DeviceName, IPAddress, SourceAccountName
// Summarization to keep potential event spam levels low
| summarize
    CurrentSyncCount = count(),
    FirstSeen = min(Timestamp),
    LastSeen  = max(Timestamp)
  by DeviceName, IPAddress, SourceAccountName
| project FirstSeen, LastSeen, CurrentSyncCount, IPAddress, SourceAccountName, DeviceName
| order by CurrentSyncCount desc, LastSeen desc
```
