# Shadow copy deletion (ransomware pre-encryption) — XDR custom detection, hourly

## Defender XDR
```kql
let Commands = dynamic(['vssadmin.exe delete shadows /all /quiet', 'wmic.exe shadowcopy delete', 'wbadmin delete catalog -quiet']);
DeviceProcessEvents
| where TimeGenerated > ago(1h)
| where FileName == "vssadmin.exe" or FileName == "wmic.exe" or FileName == "wbadmin.exe" or ProcessCommandLine has_any ("-e", "-enc", "del")
| where ProcessCommandLine has_any (Commands)
| join (DeviceNetworkEvents | where RemotePort == "445") on DeviceId
| extend Parent = tostring(parse_json(AdditionalFields)[1].value)
| summarize Hosts = make_set(DeviceName), Count = count() by DeviceName, bin(TimeGenerated, 1h)
| where Count > 3
```
