---
id: TASK-15
title: Transfer crates.io ownership of ably (and vcdiff-decode) to an org team
status: To Do
assignee: []
created_date: '2026-07-19 14:33'
labels:
  - release
  - ops
dependencies: []
priority: high
ordinal: 15000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The `ably` crate on crates.io is owned by two INDIVIDUAL accounts, not an Ably org team: `lmars` (Lewis Marshall) and `Morganamilo` (Lulu). No team owner is set. First published 2022-02-11, currently v0.2.0 (the OLD pre-rewrite library). This is a release blocker for the clean-rewrite: publishing the rewritten SDK requires push access, and today that depends on one of two personal accounts still being reachable and willing. `vcdiff-decode` (published 2026-07-19) is in the same state — owned by whoever ran `cargo publish`, no org team. Add an Ably org team as owner of both so releases aren't hostage to personal accounts, and confirm at least one current owner can still publish.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Confirm at least one existing `ably` owner can still authenticate and publish (else start a crates.io ownership-dispute/recovery request early — it is slow)
- [ ] #2 A GitHub team under the ably org is added as an owner of the `ably` crate (`cargo owner --add github:ably:<team>`)
- [ ] #3 The same org team is added as an owner of `vcdiff-decode`
- [ ] #4 Decide whether to remove the personal-account owners once the team owns both, or keep them as named maintainers (record the decision here)
<!-- AC:END -->

## Notes

- Verify ownership at any time: `cargo owner --list ably` / `cargo owner --list vcdiff-decode`, or the crates.io API (`/api/v1/crates/<name>/owner_user` and `/owner_team`).
- Adding a GitHub team owner requires the person running `cargo owner --add` to be an existing owner AND a member of that team (crates.io rule).
- Related: the rewrite still needs a version bump before publish — published `ably` is 0.2.0 (2022) and clean-rewrite's Cargo.toml is also 0.2.0; the new API is a breaking change (likely 0.3.0, or 1.0.0 if declaring the surface stable). Tracked separately from ownership but blocks the same release.
