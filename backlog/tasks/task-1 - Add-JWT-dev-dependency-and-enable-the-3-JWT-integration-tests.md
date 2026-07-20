---
id: TASK-1
title: Add JWT dev-dependency and enable the 3 JWT integration tests
status: Done
assignee: []
created_date: '2026-06-12 13:23'
updated_date: '2026-07-14 05:20'
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
- [x] #1 jsonwebtoken (or equivalent) added as dev-dependency only
- [x] #2 All 3 ignored JWT tests un-ignored and green against the live sandbox
- [x] #3 uts_coverage.txt exclusions for the JWT IDs converted to mappings
<!-- AC:END -->

## Outcome

jsonwebtoken 9 was already a dev-dependency; the gap was the fixture and the
tests. Added `generate_jwt()` (HS256, kid=keyName, x-ably-clientId claim) and
implemented all three: rsa8_jwt_token_auth, rsa8_auth_callback_jwt,
rsc10_token_renewal_with_expired_jwt — all green live. The matrix's three JWT
IDs (previously auto-mapped to plausible-but-wrong tests) now map to the real
ones. Suite: 1354 passed / 0 failed / 38 ignored.

Gotcha worth keeping: an "expired" JWT must have iat in the past too — with
iat=now and exp in the past the server derives a negative ttl and rejects the
JWT as malformed (400/40003 "Invalid value for ttl") instead of expired
(401/40142), which never triggers RSC10 renewal.
