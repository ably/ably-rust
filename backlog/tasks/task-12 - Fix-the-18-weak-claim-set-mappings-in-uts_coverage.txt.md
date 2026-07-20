---
id: TASK-12
title: Fix the 18 weak claim-set mappings in uts_coverage.txt
status: Done
assignee: []
created_date: '2026-06-12 13:47'
updated_date: '2026-07-14 04:55'
labels:
  - tests
  - traceability
  - quick-win
dependencies: []
priority: high
ordinal: 12000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
18 matrix entries map one Test ID to several same-token tests without variant verification (the generator's score-0 fallback). Spot-check proved at least one false claim: rest/unit/RSA16a/reflects-capability-1 maps to three rsa16a tests, none of which asserts capability. For each of the 18: verify the variant is genuinely covered (tighten the mapping to the single covering test) or write the missing variant test. Then make the generator emit '?? UNRESOLVED' instead of claim-sets so the class cannot reappear.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 All 18 multi-test mappings verified or replaced with new variant tests
- [x] #2 RSA16a/reflects-capability covered by a real capability assertion
- [x] #3 Generator no longer auto-claims unverified candidate sets
<!-- AC:END -->

## Outcome

The class had grown to 31 IDs (the TASK-11 integration tests added 13 more
score-0 fallbacks). Disposition: 17 verified single-test mappings, 10 new
tests, 4 exclusions (fallbackHostsUseDefault not exposed; connectivity check
is TASK-5). The generator's score-0 fallback now emits `?? UNRESOLVED` with
the candidate list, so unverified claim-sets cannot reappear; only 2 curated
multi-test mappings remain (RTB1, human-verified). Matrix: 1052 mapped /
70 excluded / 0 unresolved.

New tests: rsa16a_reflects_capability, rec2c2_explicit_hostname_endpoint_no_fallbacks,
rtn7d_pending_publishes_fail_on_disconnected_without_queueing,
rtn15e_connection_key_updated_on_resume, rtp5a_failed_clears_presence_maps,
rtp5f_suspended_maintains_presence_map, rtp15f_enter_client_mismatched_client_id_errors,
rsa7_mismatched_client_id_fails (live), rtl10b_until_attach_bounded_by_attach_point
(live behavioral proof of the fromSerial bound), plus RSL4 encoding assertions
added to the annotation wire test.

SDK bugs found and fixed by the tightened tests:
- Annotation data was sent RAW (no RSL4 encoding) on both the REST and
  realtime publish paths, and inbound/listed annotations were never decoded.
  Fixed: encode per RSL4 (no cipher) on publish/delete, decode on receipt
  (RTAN1a/RSAN1c3/RTAN4b1).
- A connect-time 40102 (token clientId incompatible with the configured
  clientId) retried forever; per RSA15c it now transitions to FAILED.
