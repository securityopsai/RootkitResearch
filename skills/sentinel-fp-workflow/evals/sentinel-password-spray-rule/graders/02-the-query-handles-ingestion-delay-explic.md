---
type: llm
focus: trace
weight: 1
---

The query handles ingestion delay explicitly: it uses ingestion_time() or declares a delay/wait window (e.g. let query_wait / ingestion_delay) that is added to the scan window
