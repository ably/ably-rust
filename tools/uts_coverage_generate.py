#!/usr/bin/env python3
"""Generate uts_coverage.txt — the UTS traceability matrix.

For every `**Test ID**` in the UTS tree (rest + realtime, unit + integration;
objects/ and docs/ are excluded by `!area` lines), emit one line:
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
    "realtime/unit/channels/channel_delta_decoding.md": "delta/vcdiff decoding not planned (needs vcdiff plugin)",
    "realtime/unit/connection/connection_recovery_test.md": "RTN16 recovery not yet implemented (planned post-5.6)",
    "realtime/unit/connection/network_change_test.md": "OS network-event detection not implemented (recorded deferral)",
    "rest/unit/push/push_channel_subscriptions.md": "push admin: LocalDevice not implemented (recorded deferral)",
    "rest/unit/push/push_channels.md": "push channels: LocalDevice not implemented (recorded deferral)",
    "realtime/integration/delta_decoding_test.md": "delta/vcdiff decoding not planned (needs vcdiff plugin)",
    "rest/integration/push_channels.md": "push channels: LocalDevice not implemented (recorded deferral)",
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
    "realtime/unit/RTB1/suspended-channel-retry-delay-1": "rtl13b_failed_reattach_suspends_and_retries, rtb1a_backoff_coefficient_sequence",
    "realtime/unit/RTN23b/heartbeats-false-query-param-0": "!! SDK consumes protocol-level heartbeats (heartbeats=true; RTN23b design choice, stage 5.2)",
    "realtime/unit/RTN23b/multiple-pings-keep-alive-6": "!! transport ping frames are not surfaced by tungstenite; protocol heartbeats used instead",
    "realtime/unit/RSA4f/callback-invalid-type-format-0": "!! unrepresentable: the typed Rust AuthCallback cannot return a wrong-typed token",
    "realtime/unit/RTF1/unrecognised-attributes-ignored-0": "rtf1_rsf1_unrecognised_attributes_ignored",
    "realtime/unit/RSF1/message-unrecognised-attrs-0": "rtf1_rsf1_unrecognised_attributes_ignored",
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
    # ---- realtime: 5.6 channel options / derived channels ----
    "realtime/unit/RTS3c/options-updated-existing-0": "rts3c_options_updated_on_existing_channel",
    "realtime/unit/RTS3c1/error-reattach-params-0": "rts3c1_get_with_conflicting_options_errors",
    "realtime/unit/RTS3c1/error-reattach-modes-1": "rts3c1_get_with_conflicting_options_errors",
    "realtime/unit/RTL16/set-options-updates-0": "rtl16_set_options_updates",
    "realtime/unit/RTL16a/triggers-reattach-0": "rtl16a_set_options_triggers_reattach",
    "realtime/unit/RTS5a/creates-derived-channel-0": "rts5a_derived_channel_name_qualification",
    "realtime/unit/RTS5a1/filter-base64-encoded-0": "rts5a_derived_channel_name_qualification",
    "realtime/unit/RTS5a2/derived-with-params-0": "rts5a2_derived_with_params_and_options",
    "realtime/unit/RTS5/get-derived-with-options-0": "rts5a2_derived_with_params_and_options",
    # ---- rest: manual mapping ----
    "rest/unit/RSAN1c6/publish-post-annotation-create-0": "rsan1c_publish_sends_post",
    # ---- realtime: 5.5 manual mappings ----
    "realtime/unit/RTL10a/supports-rest-params-0": "rtl10b_until_attach",
    "realtime/unit/RTL7f/no-echo-messages-0": "rtn2b_echo_param",
    "realtime/unit/RTL22a/filter-matching-name-0": "rtl22_message_filters",
    "realtime/unit/RTL22a/filter-matching-ref-timeserial-1": "rtl22_message_filters",
    "realtime/unit/RTL22a/filter-matching-clientid-2": "rtl22_message_filters",
    "realtime/unit/RTL22b/filter-isref-false-0": "rtl22_message_filters",
    "realtime/unit/RTL22c/filter-multiple-criteria-0": "rtl22_message_filters",
    # ---- realtime: 5.7 manual mappings ----
    "realtime/unit/RTP11d/get-suspended-errors-default-0": "rtp11d_get_suspended_semantics",
    "realtime/unit/RTP11d/get-suspended-no-wait-returns-1": "rtp11d_get_suspended_semantics",
    "realtime/unit/RTP17g/reentry-publishes-enter-with-data-0": "rtp17g1_reentry_omits_id_when_connection_changed",
    "realtime/unit/RTP17a/server-publishes-without-subscribe-0": "rtp17g1_reentry_omits_id_when_connection_changed",
    "realtime/unit/RTP6/presence-events-update-map-0": "rtp6_presence_events_update_map",
    "realtime/unit/RTP6/multiple-presence-in-single-message-1": "rtp6_presence_events_update_map",
    # ---- realtime: 5.8 manual mapping ----
    "realtime/unit/RTAN1b/publish-channel-state-0": "rtan1b_annotation_publish_state_conditions",
    # ---- TASK-11: integration mappings (each verified by reading the test) ----
    "rest/integration/RSP4b2/history-direction-forwards-0": "rsp4_presence_history",
    "rest/integration/RSP4b3/history-limit-pagination-0": "rsp4_presence_history",
    "realtime/integration/RSA9a/token-request-server-accepted-0": "rsa8_rsa9_rsa7_token_auth_connect",
    "realtime/integration/RTC8a/in-band-reauth-connected-0": "rtc8_authorize_live",
    "realtime/integration/RTC8c/authorize-initiates-connection-0": "rtc8_authorize_live",
    "realtime/integration/RTL4c/attach-succeeds-0": "live_channel_attach_detach_against_sandbox",
    "realtime/integration/RTL5d/detach-succeeds-0": "live_channel_attach_detach_against_sandbox",
    "realtime/integration/RTL6f/connectionid-matches-publisher-0": "rtl6_data_roundtrips_with_metadata",
    "realtime/integration/RSL6a2/message-extras-roundtrip-0": "rtl6_data_roundtrips_with_metadata",
    "realtime/integration/RTL7a/subscribe-all-messages-0": "rtl7_subscribe_flows_between_clients",
    "realtime/integration/RTL7b/subscribe-filtered-by-name-0": "rtl7_subscribe_flows_between_clients",
    "realtime/integration/RTAN1/annotation-publish-delete-0": "rtan_annotations_live",
    "realtime/integration/RTAN4c/annotation-type-filtering-0": "rtan_annotations_live",
    "realtime/integration/RTAN4d/annotation-implicit-attach-0": "rtan_annotations_live",
    # ---- TASK-11: integration exclusions ----
    "realtime/proxy/RTN16d/recovery-preserves-connid-0": "!! RTN16 recovery not yet implemented (planned post-5.6)",
    "realtime/proxy/RTN16l/recovery-failure-fresh-conn-0": "!! RTN16 recovery not yet implemented (planned post-5.6)",
    # ---- TASK-12: former score-0 claim-set entries, each verified by reading
    # the spec variant and the test body (or a new test was written) ----
    "rest/unit/REC1d/resthost-precedence-over-realtimehost-0": "rec1d1_rest_host_takes_precedence_over_realtime_host",
    "rest/unit/REC1d1/resthost-sets-primary-domain-0": "rec1d1_custom_rest_host",
    "rest/unit/REC2c2/explicit-hostname-no-fallbacks-0": "rec2c2_explicit_hostname_endpoint_no_fallbacks",
    "rest/unit/RSA16a/reflects-capability-1": "rsa16a_reflects_capability",
    "realtime/unit/RTAN1a/encodes-data-json-2": "rtan1a_rtan1d_annotation_publish_wire_and_ack",
    "realtime/unit/RTAN4e1/no-warn-unattached-0": "rtan4e1_skip_warning_when_attach_on_subscribe_false",
    "realtime/unit/RTL10b/adds-from-serial-0": "rtl10b_until_attach_bounded_by_attach_point",
    "realtime/unit/RTL10b/errors-when-not-attached-1": "rtl10b_until_attach",
    "realtime/unit/RTN15e/connection-key-updated-0": "rtn15e_connection_key_updated_on_resume",
    "realtime/unit/RTN7d/fail-disconnected-no-queue-0": "rtn7d_pending_publishes_fail_on_disconnected_without_queueing",
    "realtime/unit/RTN7d/survive-disconnected-queue-1": "rtn19a_rtn19a2_resend_keeps_serials_on_resume",
    "realtime/unit/RTN7e/error-represents-reason-4": "rtn7e_pending_publishes_fail_on_failed",
    "realtime/unit/RTP14a/enterclient-on-behalf-0": "rtp14a_enter_client",
    "realtime/unit/RTP15a/updateclient-leaveclient-0": "rtp15a_update_client_and_leave_client",
    "realtime/unit/RTP15f/enterclient-mismatched-clientid-0": "rtp15f_enter_client_mismatched_client_id_errors",
    "realtime/unit/RTP5a/detached-clears-presence-maps-0": "rtp5a_rtp5f_channel_state_effects",
    "realtime/unit/RTP5a/failed-clears-presence-maps-1": "rtp5a_failed_clears_presence_maps",
    "realtime/unit/RTP5f/suspended-maintains-presence-map-0": "rtp5f_suspended_maintains_presence_map",
    "realtime/unit/TM2c/connectionid-from-protocol-0": "tm2c_connection_id_populated",
    "rest/integration/RSP5/decode-history-messages-3": "rsp4_presence_history",
    "realtime/integration/RSA7/matching-clientid-succeeds-0": "rsa8_rsa9_rsa7_token_auth_connect",
    "realtime/integration/RSA7/mismatched-clientid-fails-1": "rsa7_mismatched_client_id_fails",
    "realtime/integration/RTL28/get-message-and-versions-0": "rtl32_rtl28_mutation_lifecycle_observed",
    "realtime/integration/RTL7/bidirectional-message-flow-0": "rtl7_subscribe_flows_between_clients",
    "realtime/integration/RTN11/connect-reconnect-cycle-0": "rtn4b_rtn4c_rtn11_connection_lifecycle",
    "realtime/integration/RTN4c/graceful-close-0": "rtn4b_rtn4c_rtn11_connection_lifecycle",
    # The spec's own test body IS a transport drop (delay_after_ws_connect +
    # close), the title notwithstanding
    "realtime/proxy/RTN23a/heartbeat-starvation-reconnect-0": "proxy_rtn23a_transport_failure_reconnects_with_resume",
    # ---- TASK-12: exclusions ----
    "rest/unit/REC2b/fallback-hosts-use-default-0": "!! deprecated fallbackHostsUseDefault is deliberately not exposed (as REC2a1)",
    "rest/unit/REC3/connectivity-check-validation-0": "!! connectivity check not implemented (TASK-5: RTN17j)",
    "rest/unit/REC3a/default-connectivity-check-url-0": "!! connectivity check not implemented (TASK-5: RTN17j)",
    "rest/unit/REC3b/custom-connectivity-check-url-0": "!! connectivity check not implemented (TASK-5: RTN17j)",
    # ---- rest: exclusions ----
    "rest/unit/TM2s1/version-defaults-from-message-0": "!! version defaulting deferred (recorded; ignored test exists)",
    "rest/unit/TP5/presence-message-size-0": "!! PresenceMessage::size() deferred (recorded; ignored test exists)",
    "rest/unit/RSP1b/same-instance-returned-0": "!! n/a in Rust: presence() returns a value-type accessor, instance identity is not observable",
    "rest/unit/REC2a1/fallback-hosts-conflicts-use-default-0": "!! deprecated fallbackHostsUseDefault is deliberately not exposed; the conflict cannot arise",
}

# --- collect UTS Test IDs ---
ids = []
for area in ("rest/unit", "realtime/unit", "rest/integration", "realtime/integration"):
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
# A bare fn name can exist in several modules (e.g. a unit and an integration
# variant of the same spec point) — keep every module it passes in.
passing_modules = defaultdict(set)
for p, s in results.items():
    if s == "ok":
        passing_modules[p.rsplit("::", 1)[-1]].add(
            p.rsplit("::", 1)[0] if "::" in p else ""
        )
fn_components = {name: set(name.split("_")) for name in passing}

# Integration-area Test IDs may only be claimed by tests that actually run
# against a live environment or the proxy (CLAUDE.md policy 3: a mocked unit
# test cannot honestly cover an integration ID).
def is_integration_test(name):
    return name.startswith("live_") or any(
        "integration" in m or "proxy" in m for m in passing_modules.get(name, ())
    )

def candidates(token, integration_only=False):
    t = token.lower()
    return [
        n
        for n in passing
        if t in fn_components[n] and (not integration_only or is_integration_test(n))
    ]

out_lines = []
unresolved = []

for tid, src in ids:
    if tid in OVERRIDES:
        v = OVERRIDES[tid]
        out_lines.append(f"{tid} {v}" if v.startswith("!!") else f"{tid} => {v}")
        continue
    if src in EXCLUDE_FILES:
        out_lines.append(f"{tid} !! {EXCLUDE_FILES[src]}")
        continue
    token, slug = tid.split("/")[2], tid.split("/")[3]
    integration_only = "/integration/" in tid or "/proxy/" in tid or tid.split("/")[1] in ("integration", "proxy")
    cands = candidates(token, integration_only)
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
    else:
        # No slug word discriminates a candidate: a same-token test exists but
        # nothing verifies it covers THIS variant. Claiming the candidate set
        # produced false coverage (TASK-12) — force a human disposition via
        # OVERRIDES instead.
        unresolved.append(tid)
        out_lines.append(f"{tid} ?? UNRESOLVED ({src}; same-token candidates: {', '.join(cands)})")

AREA_EXCLUSIONS = {
    "objects/unit": "LiveObjects is not implemented in this SDK (out of scope)",
    "objects/integration": "LiveObjects is not implemented in this SDK (out of scope)",
    "objects/helpers": "LiveObjects is not implemented in this SDK (out of scope)",
    "docs": "spec-authoring guide; Test IDs are illustrative examples",
}

header = """# UTS coverage matrix — one line per UTS Test ID (rest + realtime, unit +
# integration; objects/ and docs/ are dispositioned by the !area lines below).
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
area_lines = [f"!area {a} -- {r}" for a, r in sorted(AREA_EXCLUSIONS.items())]
(REPO / "uts_coverage.txt").write_text(
    header + "\n".join(area_lines) + "\n\n" + "\n".join(sorted(out_lines)) + "\n"
)
print(f"ids: {len(ids)}, unresolved: {len(unresolved)}")
for u in unresolved:
    print(" ??", u)
