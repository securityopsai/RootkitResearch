---
type: llm
focus: trace
weight: 1
---

lsass.exe and other file-name comparisons in detection.kql are case-insensitive (=~, in~, has) and the first-seen key includes a process identity stronger than the display name alone (SHA1/SHA256/signer or FolderPath)
