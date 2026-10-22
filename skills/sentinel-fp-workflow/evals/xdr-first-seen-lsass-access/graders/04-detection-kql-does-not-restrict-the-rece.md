---
type: llm
focus: trace
weight: 1
---

detection.kql does not restrict the recent-window rows with a Timestamp filter of 4h or less (XDR evaluates the lookback on ingestion_time); any explicit Timestamp bound applies only to the baseline half
