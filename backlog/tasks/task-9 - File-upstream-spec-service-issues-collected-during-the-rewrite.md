---
id: TASK-9
title: File upstream spec/service issues collected during the rewrite
status: To Do
assignee: []
created_date: '2026-06-12 13:23'
labels:
  - upstream
  - quick-win
dependencies: []
priority: high
ordinal: 9000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Flags recorded in PROGRESS.md that need filing against ably/specification and/or the realtime service: (1) SERVICE: nonprod sandbox emits duplicate map keys in msgpack MESSAGE frames — serde-strict clients drop every message; we ship a tolerant-decode workaround. (2) UTS conflict: RTP8j (wildcard enter errors) vs RTP14a/15a/15c/RTP4 setups using clientId='*' with plain enter(). (3) Corrupt RSP5g cipher fixture. (4) revoke_tokens unit mocks use the legacy array body instead of the BatchResult envelope. (5) request.md HP semantics vs token_renewal.md FAILS-WITH inconsistency.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Each of the 5 items filed (or confirmed already known) with links recorded in this task
<!-- AC:END -->
