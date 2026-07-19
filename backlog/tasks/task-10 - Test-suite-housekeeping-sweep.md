---
id: TASK-10
title: Test-suite housekeeping sweep
status: To Do
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
- [ ] Dedup per-file mock_client/get_mock helpers (12 files x ~3 each)
- [ ] Rename none_/hp_ legacy prefixes (71 fns, all in
  tests_rest_unit_misc.rs; each needs its spec ID identified AND the
  matching uts_coverage.txt mappings updated)
- [ ] Matrix regen sweep (full serial run -> tools/uts_coverage_generate.py
  -> review diff); do AFTER the renames
