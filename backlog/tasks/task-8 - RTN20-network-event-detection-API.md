---
id: TASK-8
title: RTN20 network event detection API
status: To Do
assignee: []
created_date: '2026-06-12 13:23'
labels:
  - feature
  - realtime
dependencies: []
priority: low
ordinal: 8000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
React to OS connectivity events instead of waiting for idle/heartbeat timeouts. Needs an API design decision (likely a pluggable connectivity-listener trait the host implements) since cross-platform Rust has no free primitive. 3 ignored tests; graceful degradation today via timeouts.
<!-- SECTION:DESCRIPTION:END -->
