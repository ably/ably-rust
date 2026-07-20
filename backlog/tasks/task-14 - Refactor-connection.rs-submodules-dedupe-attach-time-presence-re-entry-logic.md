---
id: TASK-14
title: >-
  Refactor connection.rs: submodules + dedupe attach-time presence/re-entry
  logic
status: Done
assignee: []
created_date: '2026-06-12 13:47'
labels:
  - maintenance
  - refactor
dependencies: []
priority: medium
ordinal: 14000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
connection.rs is 3,046 lines (handle_command 301, handle_attached 158, handle_timers 156). Split into submodules (loop core / channel arm / publish-ACK arm / presence arm) with ZERO change to the ownership model — the conformance ratchet must keep scanning all of them at allowance 0. Extract the duplicated RTP17i re-entry block and HAS_PRESENCE attach handling (each pasted twice in handle_attached) into helpers. Fold in: replace the per-op spawned oneshot-bridge tasks for presence/annotation ops with a reply enum on PendingPublish; replace raw numeric error codes (91004, 91005) with ErrorCode variants.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 No behavior change: full suite green before and after, both ratchets green
- [x] #2 tests_design_conformance.rs updated to scan the new submodule files at allowance 0
- [x] #3 RTP17i/HAS_PRESENCE logic exists exactly once
<!-- AC:END -->

## Implementation notes (2026-07-19)

- Split: src/connection.rs (3,417 lines) -> connection/mod.rs (~2,070: types,
  loop core, connect cycle, transports, timers, command/protocol dispatch) +
  channel_arm.rs (~760: ChannelCtx behaviour, attach/detach lifecycle,
  connection-state effects, inbound MESSAGE) + presence_arm.rs (~370:
  presence/annotation ops, RTP11 get, inbound PRESENCE/SYNC/ANNOTATION) +
  publish_arm.rs (~240: RTL6 pipeline, RTN19a resend, ACK/NACK). ALL state
  types stay in mod.rs — the ownership model is untouched; arms hold only
  pub(super)/pub(crate) behaviour on the same structs.
- Conformance ratchet scans all four files at allowance 0 (channel.rs still 1).
- Dedupe: ChannelCtx::apply_has_presence (RTP1/RTP19a flag handling, with a
  `publish` flag preserving each call site's snapshot behaviour) and
  ConnectionCtx::reenter_internal_members (RTP17i/RTP17g1/RTP17e) — each
  formerly pasted twice in handle_attached.
- PendingReply enum (Publish/Op) on PendingPublish replaces the per-op
  spawned oneshot-bridge tasks for presence and annotation ops; ACK/NACK/
  fail-all resolve through PendingReply::resolve. Dropped-loop behaviour is
  preserved via the callers' closed_loop_error mapping.
- Raw 91004/91005 replaced with ErrorCode::UnableToAutomaticallyReEnter-
  PresenceChannel / ErrorCode::PresenceStateIsOutOfSync.
- Suite identical before/after: unit 1246/0/26, live+proxy serial 125/0/2.
