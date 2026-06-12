---
id: TASK-7
title: Delta/vcdiff decoding plugin (RTL18-RTL20)
status: To Do
assignee: []
created_date: '2026-06-12 13:23'
labels:
  - feature
  - project
dependencies: []
priority: low
ordinal: 7000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Channels negotiating delta=vcdiff receive binary diffs needing an RFC 3284 decoder — no maintained Rust crate exists; other SDKs ship this as a plugin. Needs: decoder strategy (bind C lib vs implement), then RTL19/RTL20 discontinuity recovery. 12 ignored tests / 12 matrix exclusions.
<!-- SECTION:DESCRIPTION:END -->
