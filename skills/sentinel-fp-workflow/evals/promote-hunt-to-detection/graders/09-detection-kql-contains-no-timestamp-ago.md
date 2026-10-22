---
type: llm
focus: trace
weight: 1
---

detection.kql contains no Timestamp > ago() / Timestamp >= ago() filter on the recent rows (XDR evaluates the lookback on ingestion_time; such a filter drops late-arriving events)
