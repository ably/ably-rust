//! Design conformance ratchet (DESIGN.md "Realtime State & Concurrency" §14).
//!
//! The realtime design's central rule is that ALL mutable protocol state is
//! owned by the single connection loop, with ZERO locks on protocol state.
//! The complete allowed sync-primitive inventory is documented in DESIGN.md §1
//! and enforced here. The previous implementation accumulated 43 mutexes one
//! "harmless" lock at a time; this test fails the build on the first one.
//!
//! Changing a whitelist entry requires editing BOTH this test and DESIGN.md
//! §14 in the same commit, with human review — that is the intended trigger.

/// The realtime modules and the number of sync-primitive *occurrences*
/// (declarations or uses) each is allowed to contain.
///
/// Allowed inventory per DESIGN.md:
/// - channel.rs: one `Mutex` — the `Channels` handle registry (handles only,
///   no protocol state, never held across await) — PLUS, TEMPORARILY, the two
///   pre-design stub presence-map mutexes that ~21 ported tests poke directly.
///   Stage 5.7 supersedes those tests with UTS-derived ones and deletes the
///   fields; its PROGRESS entry must reduce this allowance from 3 to 1.
/// - everything else: zero.
///
/// tokio mpsc/oneshot/watch/broadcast are the design's sanctioned primitives
/// and are not counted.
const REALTIME_MODULES: &[(&str, &str, usize)] = &[
    ("realtime.rs", include_str!("realtime.rs"), 0),
    ("channel.rs", include_str!("channel.rs"), 3),
    ("presence.rs", include_str!("presence.rs"), 0),
    ("transport.rs", include_str!("transport.rs"), 0),
    ("protocol.rs", include_str!("protocol.rs"), 0),
];

/// Sync primitives that indicate shared mutable state outside the loop.
const FORBIDDEN: &[&str] = &[
    "std::sync::Mutex",
    "sync::Mutex<",
    "Mutex<",
    "Mutex::new",
    "RwLock",
    "AtomicBool",
    "AtomicU8",
    "AtomicU16",
    "AtomicU32",
    "AtomicU64",
    "AtomicUsize",
    "AtomicI8",
    "AtomicI16",
    "AtomicI32",
    "AtomicI64",
    "AtomicIsize",
    "AtomicPtr",
    "OnceLock",
    "OnceCell",
    "LazyLock",
    "lazy_static",
];

fn count_sync_primitives(source: &str) -> usize {
    source
        .lines()
        // Allow occurrences inside comments only when they reference the
        // design discussion, not code.
        .filter(|line| {
            let trimmed = line.trim_start();
            !trimmed.starts_with("//") && !trimmed.starts_with("//!")
        })
        .map(|line| {
            // Count at most one primitive per line: nested generics like
            // Mutex<HashMap<..>> must not double-count, while distinct locks
            // are (idiomatically) declared on distinct lines.
            usize::from(FORBIDDEN.iter().any(|p| line.contains(p)))
        })
        .sum()
}

#[test]
fn realtime_lock_inventory_matches_design() {
    let mut violations = Vec::new();
    for (name, source, allowed) in REALTIME_MODULES {
        let found = count_sync_primitives(source);
        if found > *allowed {
            violations.push(format!(
                "{}: {} sync-primitive occurrence(s), {} allowed",
                name, found, allowed
            ));
        }
    }
    assert!(
        violations.is_empty(),
        "\n\nDESIGN VIOLATION — sync primitives beyond the documented inventory:\n  {}\n\n\
         The realtime design (DESIGN.md, 'Realtime State & Concurrency') requires all\n\
         protocol state to be owned by the connection loop, with no locks on it.\n\
         If this addition is genuinely necessary, STOP: propose it as a DESIGN.md\n\
         change (§14.4), get it reviewed, and update §1/§14 plus this test's\n\
         whitelist in the same commit. Do not work around this test.\n",
        violations.join("\n  ")
    );
}

#[test]
fn realtime_state_structs_have_no_pub_fields() {
    // DESIGN.md §2: ConnectionCtx/ChannelCtx/PresenceCtx are loop-private.
    // Until they exist this passes trivially; once implemented, any `pub`
    // field on them is a design violation (handles must observe state via
    // watch snapshots, never directly).
    for (name, source, _) in REALTIME_MODULES {
        let mut in_ctx = false;
        let mut depth = 0usize;
        for line in source.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("struct ConnectionCtx")
                || trimmed.starts_with("struct ChannelCtx")
                || trimmed.starts_with("struct PresenceCtx")
                || trimmed.contains("struct ConnectionCtx")
                || trimmed.contains("struct ChannelCtx")
                || trimmed.contains("struct PresenceCtx")
            {
                in_ctx = true;
                depth = 0;
            }
            if in_ctx {
                depth += line.matches('{').count();
                assert!(
                    !(depth > 0 && trimmed.starts_with("pub ")),
                    "{}: loop-owned state struct exposes a pub field: '{}'\n\
                     (DESIGN.md §2: ConnectionCtx/ChannelCtx/PresenceCtx are loop-private)",
                    name,
                    trimmed
                );
                let closes = line.matches('}').count();
                if closes >= depth && depth > 0 {
                    in_ctx = false;
                } else {
                    depth -= closes;
                }
            }
        }
    }
}
