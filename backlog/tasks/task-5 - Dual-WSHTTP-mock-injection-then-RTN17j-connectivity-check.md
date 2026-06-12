---
id: TASK-5
title: 'Dual WS+HTTP mock injection, then RTN17j connectivity check'
status: To Do
assignee: []
created_date: '2026-06-12 13:23'
labels:
  - feature
  - test-infra
  - realtime
dependencies: []
priority: medium
ordinal: 5000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
RTN17j: before host fallback, probe the connectivity check URL to distinguish 'Ably down' from 'no internet'. The implementation is small; the blocker (recorded since 5.3) is test plumbing — Realtime::with_mock injects only the WS transport while the embedded Rest builds its own HTTP client. Add a combined injection path, then implement the probe + UTS tests.
<!-- SECTION:DESCRIPTION:END -->
