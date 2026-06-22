# Detect potential password spray attacks based on failed logon anomalies

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title | Link |
| --- | --- | --- |
| T1110.003 | Brute Force: Password Spraying | https://attack.mitre.org/techniques/T1110/003/ |

#### Description
This query detects potential password spray attacks by identifying devices where a large number of distinct user accounts experienced failed logons within a short time window. It compares the current volume of distinct failing users against a per-device baseline (calculated over the prior 7 days) and only surfaces devices whose activity exceeds the baseline by a configurable anomaly factor. Computer accounts and allowlisted devices are excluded to reduce noise.

## Defender XDR
```KQL
//Exclude device from detection  (example: dynamic(["Server01", "DC02"]))
let WhitelistByDeviceName = dynamic([]); 
// Time window for detecting suspicious activity
let TimeWindow = 3h; 
// Minimum number of failed logons per user within the time window
let MinFailuresPerUser = 2; 
// Minimum number of distinct users with failed logons on a device
let MinDistinctUsers = 200; 
// Multiplier for anomaly detection compared to baseline
let AnomalyFactor = 3.0; 
// Number of days used to calculate baseline behavior
let BaselineDays = 7d; 
let TriggeredDevices = 
IdentityLogonEvents
| where Timestamp >= ago(TimeWindow)
| where ActionType == "LogonFailed"
| where Protocol == "Ntlm" or Protocol == "Kerberos"
| where FailureReason in ("WrongPassword", "UnknownUser", "AccountDisabled", "OldPassword", "PasswordExpired", "AccountLocked", "AccountExpired")
| where DeviceName !in (WhitelistByDeviceName)
| where AccountName !endswith "$" //excluding computer accounts – their passwords are long and managed automatically
| summarize FailurePerUser = count() by DeviceName, AccountName, bin(Timestamp, TimeWindow)
| where FailurePerUser >= MinFailuresPerUser
| summarize DistinctUsers = dcount(AccountName), TotalFailures = sum(FailurePerUser) by DeviceName, Timestamp
| where DistinctUsers >= MinDistinctUsers;
let TriggeredDevicesList = TriggeredDevices
| distinct DeviceName;
let Baseline = IdentityLogonEvents
| where Timestamp between (ago(BaselineDays + TimeWindow) .. ago(TimeWindow))
| where ActionType == "LogonFailed"
| where Protocol == "Ntlm" or Protocol == "Kerberos"
| where FailureReason in ("WrongPassword", "UnknownUser", "AccountDisabled", "OldPassword", "PasswordExpired", "AccountLocked", "AccountExpired")
| where DeviceName !in (WhitelistByDeviceName)
| where DeviceName in (TriggeredDevicesList)
| where AccountName !endswith "$"
| summarize DistinctUsers = dcount(AccountName) by DeviceName, bin(Timestamp, TimeWindow)
| summarize AvgDistinctUsers = avg(DistinctUsers), StdDistinctUsers = stdev(DistinctUsers) by DeviceName;
let RawEvents =
IdentityLogonEvents
| where Timestamp >= ago(TimeWindow)
| where DeviceName  in (TriggeredDevicesList)
| where AccountName !endswith "$"
| where ActionType == "LogonFailed"
| where Protocol == "Ntlm" or Protocol == "Kerberos"
| where FailureReason in ("WrongPassword", "UnknownUser", "AccountDisabled", "OldPassword", "PasswordExpired", "AccountLocked", "AccountExpired")
| project Timestamp, DeviceName ,Protocol, AccountName, AccountDomain, IPAddress, ActionType, DestinationDeviceName, DestinationIPAddress, FailureReason;
TriggeredDevices
| join kind=leftouter Baseline on DeviceName
| extend AvgDistinctUsers = coalesce(AvgDistinctUsers, 0.0)
| extend StdDistinctUsers = coalesce(StdDistinctUsers, 0.0)
| where DistinctUsers > AvgDistinctUsers + StdDistinctUsers * AnomalyFactor
| join kind=inner (
    RawEvents
    | extend WindowTime = bin(Timestamp, TimeWindow)
) on DeviceName
| summarize
    Accounts = make_set(AccountName),
    IPAddress = make_set(IPAddress)
    by DeviceName, Timestamp, DistinctUsers, TotalFailures
| summarize arg_max(Timestamp, *) by DeviceName
| project Timestamp, DeviceName, DistinctUsers, TotalFailures, Accounts, IPAddress
```
