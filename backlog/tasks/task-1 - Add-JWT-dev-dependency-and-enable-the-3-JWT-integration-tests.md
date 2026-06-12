---
id: TASK-1
title: Add JWT dev-dependency and enable the 3 JWT integration tests
status: To Do
assignee: []
created_date: '2026-06-12 13:23'
labels:
  - tests
  - quick-win
dependencies: []
priority: high
ordinal: 1000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
rsa8_jwt_token_auth, rsc10_token_renewal_with_expired_jwt, and the authCallback+JWT test are ignored because we cannot mint a JWT fixture. Token auth itself is fully implemented; this is purely a test-fixture gap.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 jsonwebtoken (or equivalent) added as dev-dependency only
- [ ] #2 All 3 ignored JWT tests un-ignored and green against the live sandbox
- [ ] #3 uts_coverage.txt exclusions for the JWT IDs converted to mappings
<!-- AC:END -->
