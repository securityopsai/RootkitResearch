---
type: llm
focus: trace
weight: 1
---

No behaviour query matches the full sample command line verbatim or relies solely on sample-specific strings (the task name 'OneDrive Sync Health', 'upd.exe', the fictional hash) — behaviour queries anchor on the process (conhost/powershell/schtasks via FileName) and a few invariant tokens such as --headless, irm/iex, /create with an AppData\Roaming path
