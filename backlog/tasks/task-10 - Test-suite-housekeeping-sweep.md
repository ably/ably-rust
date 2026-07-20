---
id: TASK-10
title: Test-suite housekeeping sweep
status: Done
assignee: []
created_date: '2026-06-12 13:23'
labels:
  - maintenance
  - tests
dependencies: []
priority: low
ordinal: 10000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Older recorded deferrals from R5/R6: sandbox app teardown after integration runs; dedup the per-file mock_client/get_mock test_support helpers; rename the none_/hp legacy test prefixes to spec-pointed names. Also: periodically regenerate uts_coverage.txt against a fresh full-suite run and review the diff (the matrix is curated).
<!-- SECTION:DESCRIPTION:END -->

## Progress

- [x] Sandbox app teardown (2026-07-19): get_sandbox() registers a
  libc::atexit handler on first provision; the handler issues a blocking
  DELETE /apps/{appId} via ureq with basic key auth. NO async runtime may
  exist inside the handler — reqwest's blocking client spins one up and
  aborts the process at exit (verified the hard way); ureq is purely
  blocking (threads + sockets), so it is safe there. Failures degrade gracefully (apps
  are autodelete-labelled). Verified live: "sandbox teardown: deleted app
  _tmp_uWevcQ (204)".
- [x] Dedup helpers (2026-07-19): the hash-identical mock_client/get_mock/
  mock_client_json trio from 12 files now lives once in test_support.rs
- [x] Renamed the 71 none_ tests (2026-07-19): 65 matched to verified spec
  IDs against features.md; 6 pure-Rust-mechanics tests named plainly (no
  fake IDs). None were referenced by the matrix. (No hp_ fns remained.)
- [x] Matrix regen sweep (2026-07-19): full serial run (1371/0/28) ->
  generator -> diff review caught 6 regressions, root-caused to stale
  OVERRIDES in tools/uts_coverage_generate.py (tasks 2/3/5 updated the
  matrix but not the generator's dispositions) plus one auto-match drift
  from the renames (RSP4a/history-returns-paginated-1 — pinned to the
  verified test). OVERRIDES fixed; regen is now byte-identical to the
  curated file. LESSON: when converting a matrix exclusion, update the
  generator's OVERRIDES in the same change.
