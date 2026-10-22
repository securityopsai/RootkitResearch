---
type: llm
focus: trace
weight: 1
---

detection.kql computes the 'seen before' baseline from a window that ends before the recent window starts (a guard gap such as between(ago(30d)..ago(1d)) vs > ago(1d)), not an overlapping window
