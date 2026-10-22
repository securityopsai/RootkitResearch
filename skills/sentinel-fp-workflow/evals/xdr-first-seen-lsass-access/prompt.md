---
tags: [skill-creator]
max_turns: 30
timeout_seconds: 900
allowed_tools: [Read, Glob, Grep, Skill, Write, Edit, Bash]
---

I need a Defender XDR custom detection rule that fires when a process that has never been seen accessing lsass.exe anywhere in our fleet before does so. It should run hourly. Save the KQL as detection.kql and write a short rule document (rule.md) that a reviewer could use: what it detects, MITRE mapping, the tuning knobs, known false positives, and what it would miss.
