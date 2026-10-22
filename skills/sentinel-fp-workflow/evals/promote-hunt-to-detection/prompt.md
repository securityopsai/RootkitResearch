---
tags: [skill-creator]
max_turns: 30
timeout_seconds: 900
allowed_tools: [Read, Glob, Grep, Skill, Write, Edit, Bash]
---

This hunting query (hunt.kql) has been useful and we want it as a Defender XDR custom detection running every hour; we will also deploy a Sentinel scheduled rule version later. Convert it: output detection.kql (the XDR version) and a short promotion-notes.md explaining what you changed and why, and what to watch after deployment.

Input files: hunt.kql
