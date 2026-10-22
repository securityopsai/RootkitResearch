---
tags: [skill-creator]
max_turns: 30
timeout_seconds: 900
allowed_tools: [Read, Glob, Grep, Skill, Write, Edit, Bash]
---

Write a Microsoft Sentinel scheduled analytics rule, as a YAML file rule.yaml in the Azure-Sentinel repository format with the KQL inline, that detects password spray against Entra ID from a single source IP using SigninLogs. It should run every hour. Make it something I could deploy without surprises.
