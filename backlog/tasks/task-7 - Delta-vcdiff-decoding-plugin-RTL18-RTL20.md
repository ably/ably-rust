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

## Decoder strategy — RESOLVED (2026-07-19)

- Decision: implement, not bind C. A clean-room pure-Rust decoder lives at
  https://github.com/ably/vcdiff-rust (reviewed in PR #1; merged). Zero
  runtime deps. Passes all 85 shared vcdiff-tests conformance cases + fuzz.
- Crate: publishes to crates.io as **`vcdiff-decode`** (the bare `vcdiff`
  name is a dead 2016 open-vcdiff binding; `vcdiff-decoder` is a 2024
  crate). Import path is `vcdiff` (explicit `[lib] name`): declare
  `vcdiff-decode = "1"`, write `use vcdiff::...`. (PR #2, merged.)
- CONSUMPTION: `ably` publishes to crates.io, which forbids git deps in
  published crates, so `ably` must depend on `vcdiff-decode` FROM crates.io
  — i.e. the crate must be `cargo publish`ed before `ably` ships delta
  support. (Publish is a manual release step, pending.)
- Still to decide when implementing: bundled optional dep (`ably` +
  `vcdiff` feature) vs injectable plugin (app depends on vcdiff-decode and
  passes a decoder in, like ably-js/@ably/vcdiff-decoder). Either way the
  crate must be on crates.io.

## API notes for the integration (from the PR #1 review)

- `decode(source, delta) -> Result<Vec<u8>, VcdiffError>`; also
  VcdiffDecoder (reusable), StreamingDecoder (append/finish), parse_delta.
- RTL18/RTL19: a failed decode (VcdiffError, notably ChecksumMismatch)
  must trigger the discontinuity path — request a fresh non-delta message,
  not silently drop.
- Untrusted input: the decoder can PANIC on malformed deltas (u32 overflow
  arithmetic; wraps in release, panics in debug — same as the Go
  reference). Server deltas are attacker-influenceable, so wrap decode in
  catch_unwind at the SDK boundary (or push a hardening pass upstream)
  before feeding it live data.
- KNOWN GAP: VCD_TARGET (a window sourcing its segment from the decoded
  target) is accepted-but-unimplemented in both our crate and the Go
  reference, and untested by the shared suite. Multi-window VCD_SOURCE IS
  supported/tested (19 fixtures). Confirm whether Ably's server-side delta
  encoder ever emits VCD_TARGET windows before relying on this in prod
  (capture real deltas and check the 0x02 win-indicator bit).
