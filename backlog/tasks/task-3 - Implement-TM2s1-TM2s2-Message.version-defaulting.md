---
id: TASK-3
title: Implement TM2s1/TM2s2 Message.version defaulting
status: Done
assignee: []
created_date: '2026-06-12 13:23'
labels:
  - quick-win
  - types
dependencies: []
priority: medium
ordinal: 3000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
When a REST message arrives without a version on the wire, synthesize Message.version from the message's own serial and timestamp. Un-ignore the version-defaulting test; convert the TM2s1 matrix exclusion.
<!-- SECTION:DESCRIPTION:END -->
