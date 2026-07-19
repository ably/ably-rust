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
Flags recorded in PROGRESS.md that need filing against ably/specification and/or the realtime service: (1) SERVICE: nonprod sandbox emits duplicate map keys in msgpack MESSAGE frames — serde-strict clients drop every message; we ship a tolerant-decode workaround. (2) UTS conflict: RTP8j (wildcard enter errors) vs RTP14a/15a/15c/RTP4 setups using clientId='*' with plain enter(). (3) Corrupt RSP5g cipher fixture. (4) revoke_tokens unit mocks use the legacy array body instead of the BatchResult envelope. (5) request.md HP semantics vs token_renewal.md FAILS-WITH inconsistency. (6) RTN15h1 error-code conflict: unit spec `connection_failures_test.md` asserts errorReason.code == 40142 (pass-through of the server's token error), but the proxy integration spec `connection_resume.md` asserts 40171 with an explicit note that ably-js substitutes "no way to renew" — the unit spec should be updated to 40171. Our SDK and both tests follow the 40171 behaviour.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Each of the 6 items filed (or confirmed already known) with links recorded in this task
<!-- AC:END -->

## Re-evaluation against specification@main (2da26476-era, 2026-07-19)

UTS is now upstream on ably/specification main, and main's
`uts/docs/writing-derived-tests.md` (commit 1da26476) mandates SPEC-FIRST
handling: UTS spec errors are fixed at source in the spec repo and recorded
in the SDK's deviations file (UTS Spec Errors section) — not merely filed as
observations. Per-item status on latest main:

1. SERVICE msgpack duplicate keys — UNAFFECTED by the spec repo; still needs
   an internal service ticket. Open question: does prod emit them too?
2. RTP8j wildcard conflict — MOSTLY FIXED upstream: the RTP14a/15a/15c/RTP4
   setups now use enterClient with a top-level adaptation note for SDKs that
   reject "*" at construction. RESIDUAL: RTP15c
   `realtime/unit/RTP15c/enterclient-no-side-effects-0`
   (realtime_presence_enter.md ~line 938) still calls plain `enter(data:)`
   with clientId "*" and asserts success — contradicts RTP8j/features spec
   ("wildcard → enter errors immediately"). One-line fix: concrete clientId
   (reentry.md already does exactly this).
3. RSP5g cipher fixture — STILL CORRUPT on main: rest_presence.md has
   "HO4cYSP8LybPYBPZPHQOtuD53yrD3YV3NBoTEYBh4U0=" (32 bytes), a truncation
   of the canonical ably-common fixture
   "HO4cYSP8LybPYBPZPHQOtuD53yrD3YV3NBoTEYBh4U0N1QXHbtkfsDfTspKeLQFt"
   (48 bytes) that our rsp5g test uses.
4. revoke_tokens legacy array mocks — FIXED upstream: revoke_tokens.md now
   mandates and uses the BatchResult envelope. CLOSED, nothing to file.
5. request.md HP vs token_renewal.md — RESOLVED upstream: token_renewal.md
   no longer routes failure flows through request() (uses history()/
   status()). CLOSED, nothing to file.
6. RTN15h1 40142 vs 40171 — STILL PRESENT: connection_failures_test.md line
   ~82 asserts errorReason.code == 40142; connection_resume.md ~516-520
   asserts 40171. The features spec settles it: RSA4a2 says "indicate an
   error with error code 40171 ... transition the connection to the FAILED
   state". The unit spec is the one in error; fix to 40171.

Revised scope: ONE spec PR fixing items 2-residual, 3 and 6 (all small,
authority-backed); ONE internal service ticket for item 1 (after checking
prod behaviour). Items 4 and 5 need no action.

FILED 2026-07-19: https://github.com/ably/specification/pull/507 covers all
spec-side items. Scope grew during drafting: RSA7c reserves "*" as a
ClientOptions#clientId value, so EVERY `clientId: "*"` setup in
realtime_presence_enter.md was unrunnable on a compliant SDK — the PR fixes
the whole class (enterClient tests -> unidentified key auth; RTP8j wildcard
via wildcard token; RTP15c -> two clients since RTP8j + RTP15f mean no single
clientId permits both enter() and enterClient(other); reentry.md's identified
"admin" + enterClient(other) also violated RTP15f). Cross-checked against
ably-js test/uts on main: their RTP15c adaptation only passes because they
skip the client-side RTP15f check; their RTN15h1 unit test omits the code
assertion; their RSP5g is skipped (cipher TODO). ably-js's realtime-audit.md
items were all verified fixed on current mains (their audit item 9 partly
mis-blamed channel_connection_state.md — its suspendedRetryTimeout usage is
connection-level and correct).

REMAINING: (a) item 1 service ticket — check prod for duplicate msgpack keys
first; (b) after PR merge: re-derive our rtp15c/rtp8j-wildcard tests to the
new spec shapes and drop the stale "unit spec contradicts" comment in
rtn15h1_disconnected_token_error_without_renewal_fails; (c) optional small
ably-js follow-up PR (re-translate RTP15c, add 40171 assertion).

ROOT CAUSE FOUND (2026-07-19), item 1 — Go frontdoor:
`roles/frontdoor/protocol/protocol_message.go`, `marshalCommon`. For MESSAGE
actions it encodes `struct { *Alias; Messages any }` where both the embedded
Alias's `Messages` field and the outer `Messages` carry the tag
`json:"messages,omitempty"` (MarshalMsgpack uses vmihailenco/msgpack v5.4.1
with SetCustomStructTag("json")). encoding/json resolves the collision by
depth (outer shadows embedded — one key); vmihailenco inlines embedded
fields WITHOUT shadowing and emits BOTH — it even logs "msgpack: struct
{...} already has field=messages" (greppable in frontdoor logs) but encodes
anyway. JSON clean, msgpack duplicated — the exact observed symptom. The
SYNC branch has the identical pattern with `presence` (duplicate whenever
p.Presence is non-empty). Values are byte-identical (both fields reference
p.Messages), so last-wins dedup is safe.
- Standalone repro (v5.4.1): hexdump shows map header 0x84 with "messages"
  twice; JSON has it once.
- LIVE CAPTURE from sandbox: first MESSAGE frame received had top-level keys
  [action id channel channelSerial connectionId messages timestamp messages];
  raw frame + hexdump saved at
  `/Users/paddy/data/worknew/dev/rust-experiments/duplicate-key-frame.{bin,hex}`.
- Suggested fix: only apply the wrapper when it is needed (MessagesV3
  non-empty for MESSAGE; p.Presence empty for SYNC) and encode the plain
  Alias otherwise — the "only one populated" guarantee then makes omitempty
  drop the embedded field, leaving exactly one key in both formats.
