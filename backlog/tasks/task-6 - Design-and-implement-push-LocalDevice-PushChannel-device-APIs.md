---
id: TASK-6
title: Design and implement push LocalDevice + PushChannel device APIs
status: To Do
assignee: []
created_date: '2026-06-12 13:23'
labels:
  - feature
  - push
  - project
dependencies: []
priority: low
ordinal: 6000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Push ADMIN REST APIs are done. Deferred: the device-side half — LocalDevice needs persistent device state (identity, registration token, platform credentials), i.e. a storage abstraction decision for a Rust SDK. Blocks: PushChannel.subscribeDevice/subscribeClient (RSH7, 10 ignored tests), Realtime.push delegation (RTC13), 2 LocalDevice integration tests. Start with the storage-trait design decision.
<!-- SECTION:DESCRIPTION:END -->
