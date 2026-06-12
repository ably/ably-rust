---
id: TASK-12
title: Fix the 18 weak claim-set mappings in uts_coverage.txt
status: To Do
assignee: []
created_date: '2026-06-12 13:47'
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
- [ ] #1 All 18 multi-test mappings verified or replaced with new variant tests
- [ ] #2 RSA16a/reflects-capability covered by a real capability assertion
- [ ] #3 Generator no longer auto-claims unverified candidate sets
<!-- AC:END -->
