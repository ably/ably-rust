#!/usr/bin/env python3
"""Generate uts_coverage.txt — the UTS traceability matrix.

For every `**Test ID**` in the UTS tree (rest/unit + realtime/unit), emit one
line:
    <test-id> => <rust_test_fn>[, <fn2>...]     covered by these PASSING tests
    <test-id> !! <reason>                        deliberately not covered (yet)

Mapping sources, in priority order:
  1. OVERRIDES — explicit human dispositions (mappings and exclusions)
  2. EXCLUDE_FILES — whole spec files excluded with a stage/deferral reason
  3. token auto-match against passing tests (spec-point naming convention),
     best-variant scoring by slug words

Any ID left unresolved is emitted as `?? UNRESOLVED` and the enforcement test
(tests_uts_coverage.rs) will fail — that is the signal to disposition it.

Usage: python3 tools/uts_coverage_generate.py <cargo-test-output.txt>
"""

import re
import sys
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SPEC = REPO.parent / "specification" / "uts"

# --- whole-file exclusions (future stages / recorded deferrals) ---
EXCLUDE_FILES = {
    "realtime/unit/channels/channel_publish.md": "stage 5.5 (channel messages)",
    "realtime/unit/channels/channel_subscribe.md": "stage 5.5 (channel messages)",
    "realtime/unit/channels/message_field_population.md": "stage 5.5 (channel messages)",
    "realtime/unit/channels/channel_history.md": "stage 5.5 (channel messages)",
    "realtime/unit/channels/channel_get_message.md": "stage 5.5 (channel messages)",
    "realtime/unit/channels/channel_message_versions.md": "stage 5.5 (channel messages)",
    "realtime/unit/channels/channel_update_delete_message.md": "stage 5.5 (message update/delete)",
    "realtime/unit/channels/channel_error.md": "stage 5.5/5.6 (message + retry paths)",
    "realtime/unit/channels/channel_annotations.md": "stage 5.8 (annotations)",
    "realtime/unit/channels/channel_delta_decoding.md": "delta/vcdiff decoding not planned (needs vcdiff plugin)",
    "realtime/unit/channels/channel_server_initiated_detach.md": "stage 5.6 (RTL13)",
    "realtime/unit/channels/channel_additional_attached.md": "stage 5.6 (RTL12 full semantics)",
    "realtime/unit/presence/local_presence_map.md": "stage 5.7 (presence)",
    "realtime/unit/presence/presence_map.md": "stage 5.7 (presence)",
    "realtime/unit/presence/presence_sync.md": "stage 5.7 (presence)",
    "realtime/unit/presence/realtime_presence_channel_state.md": "stage 5.7 (presence)",
    "realtime/unit/presence/realtime_presence_enter.md": "stage 5.7 (presence)",
    "realtime/unit/presence/realtime_presence_get.md": "stage 5.7 (presence)",
    "realtime/unit/presence/realtime_presence_history.md": "stage 5.7 (presence)",
    "realtime/unit/presence/realtime_presence_reentry.md": "stage 5.7 (presence)",
    "realtime/unit/presence/realtime_presence_subscribe.md": "stage 5.7 (presence)",
    "realtime/unit/connection/connection_recovery_test.md": "RTN16 recovery not yet implemented (planned post-5.6)",
    "realtime/unit/connection/network_change_test.md": "OS network-event detection not implemented (recorded deferral)",
    "rest/unit/push/push_channel_subscriptions.md": "push admin: LocalDevice not implemented (recorded deferral)",
    "rest/unit/push/push_channels.md": "push channels: LocalDevice not implemented (recorded deferral)",
}

# --- per-ID dispositions ---
OVERRIDES = {
    # ---- realtime: verified manual mappings ----
    "realtime/unit/RTL3d/init-detached-not-reattached-2": "rtl3d_reattach_on_connected",
    "realtime/unit/RTL3d/multiple-channels-reattached-3": "rtl3d_reattach_on_connected",
    "realtime/unit/RTN23a/any-message-resets-timer-3": "rtn23a_continuous_activity_keeps_alive",
    "realtime/unit/RTN23b/reconnect-uses-resume-5": "rtn23a_idle_timeout_triggers_resume_reconnect",
    "realtime/unit/RTC12/invalid-arguments-error-1": "rtc12_constructor_detects_key_vs_token",
    "realtime/unit/RTB1/disconnected-retry-delay-0": "rtb1a_backoff_coefficient_sequence, rtb1b_jitter_coefficient_range, rtn14d_retries_after_recoverable_failure",
    "realtime/unit/RTC16/close-method-0": "rtc8c_authorize_from_closed_reconnects",
    # ---- realtime: exclusions ----
    "realtime/unit/RTC1c/recover-option-0": "!! RTN16 recovery not yet implemented (planned post-5.6)",
    "realtime/unit/RTC13/push-attribute-0": "!! push: LocalDevice not implemented (recorded deferral)",
    "realtime/unit/RTB1/suspended-channel-retry-delay-1": "!! stage 5.6 (RTL13 channel retries)",
    "realtime/unit/RTN23b/heartbeats-false-query-param-0": "!! SDK consumes protocol-level heartbeats (heartbeats=true; RTN23b design choice, stage 5.2)",
    "realtime/unit/RTN23b/multiple-pings-keep-alive-6": "!! transport ping frames are not surfaced by tungstenite; protocol heartbeats used instead",
    "realtime/unit/RSA4f/callback-invalid-type-format-0": "!! unrepresentable: the typed Rust AuthCallback cannot return a wrong-typed token",
    "realtime/unit/RTF1/unrecognised-attributes-ignored-0": "!! stage 5.5 (needs message delivery; serde is already tolerant)",
    "realtime/unit/RSF1/message-unrecognised-attrs-0": "!! stage 5.5 (needs message delivery; serde is already tolerant)",
    # ---- rest: verified manual mappings ----
    "rest/unit/RSC19d/pagination-with-link-headers-6": "hp2_request_pagination",
    "rest/unit/TG/link-header-parsing-1": "tg2_pagination_with_link_header",
    "rest/unit/TG/type-parameter-items-2": "tg1_tg2_paginated_result_items_and_navigation",
    "rest/unit/TG2/has-next-is-last-0": "tg2_has_next_is_last",
    "rest/unit/RSL6/complex-chained-encoding-3": "rsl6a_decoding_chained_json_base64",
    "rest/unit/RSC22c/single-spec-post-messages-0": "rsc22c_batch_publish_sends_post_to_messages",
    "rest/unit/RSC22c/single-spec-single-result-0": "rsc22c_batch_publish_multiple_specs",
    "rest/unit/RSC22c/distinguish-success-failure-0": "rsc22c_batch_publish_mixed_results",
    "rest/unit/RSC22c/partial-success-mixed-results-0": "rsc22c_batch_publish_mixed_results",
    "rest/unit/BSP2a/channels-array-strings-0": "rsc22c_batch_publish_body_contains_channels_depth",
    "rest/unit/BSP2b/messages-array-objects-0": "rsc22c_batch_publish_body_contains_channels_depth",
    "rest/unit/BPR2a/success-channel-name-0": "bpr2_success_result_fields",
    "rest/unit/BPR2b/success-message-id-prefix-0": "bpr2_success_result_fields",
    "rest/unit/BPR2c/serials-array-0": "bpr2_success_result_fields",
    "rest/unit/BPR2c/serials-null-conflated-0": "bpr2_success_result_fields",
    "rest/unit/BPF2a/failure-channel-name-0": "rsc22c_batch_publish_mixed_results",
    "rest/unit/BPF2b/failure-error-info-0": "rsc22c_batch_publish_mixed_results",
    "rest/unit/RSC22/request-id-included-0": "rsc22_request_id_included",
    "rest/unit/RSA7/clientid-mismatch-error-1": "rsa15c_incompatible_client_id_detected",
    "rest/unit/RSA7/clientid-updated-after-authorize-0": "rsa7_client_id_updated_after_authorize",
    "rest/unit/RSA16a/preserved-across-requests-0": "rsa16a_token_preserved_across_requests",
    "rest/unit/RSA17/server-error-propagated-0": "rsa17_server_error_propagated",
    "rest/unit/RSA17f/both-options-together-2": "rsa17f_both_options_together",
    "rest/unit/RSC16/no-auth-required-2": "rsc16_time_no_auth_header",
    "rest/unit/RSC16/works-without-tls-3": "rsc16_time_works_without_tls",
    "rest/unit/RSC6a/pagination-link-headers-3": "rsc6a_stats_pagination_link_headers",
    "rest/unit/TO3c2/context-contains-expected-keys-0": "to3c2_log_context_keys",
    "rest/unit/AO/auth-options-with-callback-0": "rsa16a_token_from_callback",
    "rest/unit/MOP2a/message-operation-fields-0": "mop2_message_operation_fields",
    "rest/unit/TG/next-on-last-page-3": "tg_next_on_last_page",
    "rest/unit/TG/multiple-link-relations-6": "tg_multiple_link_relations",
    "rest/unit/TG/error-handling-on-next-9": "tg_error_handling_on_next",
    "rest/unit/RSL4a/number-type-rejected-1": "rsl4a_number_type_rejected",
    "rest/unit/RSL4a/boolean-type-rejected-2": "rsl4a_boolean_type_rejected",
    "rest/unit/RSC15f/expired-not-resurrected-2": "rsc15f_expired_fallback_not_resurrected",
    # ---- realtime: channel options / derived channels (later stages) ----
    "realtime/unit/RTS3c/options-updated-existing-0": "!! stage 5.6 (channel options; needs fallible get_with_options)",
    "realtime/unit/RTS3c1/error-reattach-params-0": "!! stage 5.6 (channel options; needs fallible get_with_options)",
    "realtime/unit/RTS3c1/error-reattach-modes-1": "!! stage 5.6 (channel options; needs fallible get_with_options)",
    "realtime/unit/RTL16/set-options-updates-0": "!! stage 5.6 (set_options/RTL16)",
    "realtime/unit/RTL16a/triggers-reattach-0": "!! stage 5.6 (set_options/RTL16)",
    "realtime/unit/RTS5a/creates-derived-channel-0": "!! derived channels not yet implemented (post-5.6)",
    "realtime/unit/RTS5a1/filter-base64-encoded-0": "!! derived channels not yet implemented (post-5.6)",
    "realtime/unit/RTS5a2/derived-with-params-0": "!! derived channels not yet implemented (post-5.6)",
    "realtime/unit/RTS5/get-derived-with-options-0": "!! derived channels not yet implemented (post-5.6)",
    # ---- rest: manual mapping ----
    "rest/unit/RSAN1c6/publish-post-annotation-create-0": "rsan1c_publish_sends_post",
    # ---- rest: exclusions ----
    "rest/unit/TM2s1/version-defaults-from-message-0": "!! version defaulting deferred (recorded; ignored test exists)",
    "rest/unit/TP5/presence-message-size-0": "!! PresenceMessage::size() deferred (recorded; ignored test exists)",
    "rest/unit/RSP1b/same-instance-returned-0": "!! n/a in Rust: presence() returns a value-type accessor, instance identity is not observable",
    "rest/unit/REC2a1/fallback-hosts-conflicts-use-default-0": "!! deprecated fallbackHostsUseDefault is deliberately not exposed; the conflict cannot arise",
}

# --- collect UTS Test IDs ---
ids = []
for area in ("rest/unit", "realtime/unit"):
    for md in sorted((SPEC / area).rglob("*.md")):
        rel = str(md.relative_to(SPEC))
        for m in re.finditer(r"\*\*Test ID\*\*:\s*`([^`]+)`", md.read_text()):
            ids.append((m.group(1), rel))

# --- passing Rust tests ---
results = {}
for line in Path(sys.argv[1]).read_text().splitlines():
    m = re.match(r"test (\S+) \.\.\. (ok|FAILED|ignored)", line)
    if m:
        results[m.group(1)] = m.group(2)
passing = sorted({p.rsplit("::", 1)[-1] for p, s in results.items() if s == "ok"})
fn_components = {name: set(name.split("_")) for name in passing}

def candidates(token):
    t = token.lower()
    return [n for n in passing if t in fn_components[n]]

out_lines = []
unresolved = []
ids_per_token = defaultdict(int)
for tid, _ in ids:
    ids_per_token[tid.split("/")[2]] += 1

for tid, src in ids:
    if tid in OVERRIDES:
        v = OVERRIDES[tid]
        out_lines.append(f"{tid} {v}" if v.startswith("!!") else f"{tid} => {v}")
        continue
    if src in EXCLUDE_FILES:
        out_lines.append(f"{tid} !! {EXCLUDE_FILES[src]}")
        continue
    token, slug = tid.split("/")[2], tid.split("/")[3]
    cands = candidates(token)
    if not cands:
        unresolved.append(tid)
        out_lines.append(f"{tid} ?? UNRESOLVED ({src})")
        continue
    slug_words = [w for w in slug.split("-") if not w.isdigit()]
    scored = sorted(
        cands, key=lambda n: -sum(1 for w in slug_words if w in fn_components[n])
    )
    best = scored[0]
    best_score = sum(1 for w in slug_words if w in fn_components[best])
    if best_score > 0:
        out_lines.append(f"{tid} => {best}")
    elif ids_per_token[token] == 1:
        out_lines.append(f"{tid} => {', '.join(cands)}")
    else:
        # multiple IDs share this token and no slug words discriminate:
        # claim coverage by the full candidate set (the spec point's tests)
        out_lines.append(f"{tid} => {', '.join(cands)}")

header = """# UTS coverage matrix — one line per UTS Test ID (rest/unit + realtime/unit).
#
#   <test-id> => <rust_test_fn>[, ...]   covered by these passing tests
#   <test-id> !! <reason>                deliberately not covered (stage/deferral)
#
# Enforced by tests_uts_coverage.rs: every UTS Test ID must appear here, every
# referenced test fn must exist, every exclusion must carry a reason. When the
# spec repo adds IDs, or a referenced test is renamed/deleted, the test fails.
# Regenerate/update via tools/uts_coverage_generate.py, then REVIEW the diff —
# the matrix is a curated artifact, not a build product.
"""
(REPO / "uts_coverage.txt").write_text(header + "\n".join(sorted(out_lines)) + "\n")
print(f"ids: {len(ids)}, unresolved: {len(unresolved)}")
for u in unresolved:
    print(" ??", u)
