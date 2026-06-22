# Detect when an account has been changed in order for the password to never expire

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title | Link |
| --- | --- | --- |
| T1098 | Account Manipulation | https://attack.mitre.org/techniques/T1098/ |

#### Description
This query detects when an account's UAC flags was set to Account Password Never Expires.

## Defender XDR
```KQL
IdentityDirectoryEvents
| where ActionType == "Account Password Never Expires changed"
| extend AdditionalInfo = parse_json(AdditionalFields)
| extend OriginalValue = AdditionalInfo.['FROM Account Password Never Expires'],  NewValue = AdditionalInfo.['TO Account Password Never Expires'], AccountSid = AdditionalFields.TargetAccountSid
| where NewValue == true
| project-reorder Timestamp, TargetAccountUpn, AccountSid, OriginalValue, NewValue, ReportId, DeviceName
```
