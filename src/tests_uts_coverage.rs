#![cfg(test)]

//! UTS coverage ratchet (companion to tests_design_conformance.rs).
//!
//! `uts_coverage.txt` is the traceability matrix: one line per UTS Test ID,
//! either mapped to the Rust test(s) that cover it or excluded with a reason.
//! This test fails when the matrix and reality diverge:
//!   - the spec repo defines a Test ID the matrix doesn't account for
//!   - the matrix references a Test ID the spec repo no longer defines
//!   - a mapped Rust test function no longer exists (renamed/deleted)
//!   - an exclusion has no reason, or an UNRESOLVED marker remains
//!
//! Closing a stage means turning that stage's exclusions into mappings.
//! Update the matrix by hand or via tools/uts_coverage_generate.py — and
//! review the diff; the matrix is a curated artifact.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

fn spec_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("UTS_SPEC_DIR") {
        return PathBuf::from(dir);
    }
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../specification/uts")
}

fn collect_md_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_md_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "md") {
            out.push(path);
        }
    }
}

/// Every directory under uts/ that contains Test IDs. The matrix must trace
/// each area's IDs or carry an explicit `!area <name> -- <reason>` line
/// (CLAUDE.md engineering policy 2: the whole spec tree is dispositioned).
fn discover_areas(spec: &Path) -> BTreeSet<String> {
    let mut areas = BTreeSet::new();
    let Ok(entries) = std::fs::read_dir(spec) else {
        return areas;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        // areas are one or two levels deep (rest/unit, rest/integration, …)
        let mut subdirs = Vec::new();
        if let Ok(subs) = std::fs::read_dir(&path) {
            for sub in subs.flatten() {
                if sub.path().is_dir() {
                    subdirs.push(format!("{}/{}", name, sub.file_name().to_string_lossy()));
                }
            }
        }
        let candidates = if subdirs.is_empty() {
            vec![name.clone()]
        } else {
            let mut c = subdirs;
            c.push(name.clone());
            c
        };
        for area in candidates {
            let mut files = Vec::new();
            collect_md_files(&spec.join(&area), &mut files);
            let has_ids = files.iter().any(|f| {
                std::fs::read_to_string(f)
                    .map(|t| t.contains("**Test ID**"))
                    .unwrap_or(false)
            });
            if has_ids {
                areas.insert(area);
            }
        }
    }
    // keep only the most specific areas (drop a parent when a child exists)
    let specific: BTreeSet<String> = areas
        .iter()
        .filter(|a| !areas.iter().any(|b| b.starts_with(&format!("{}/", a))))
        .cloned()
        .collect();
    specific
}

fn collect_area_ids(spec: &Path, area: &str) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    let mut files = Vec::new();
    collect_md_files(&spec.join(area), &mut files);
    for file in files {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        let mut rest = text.as_str();
        while let Some(pos) = rest.find("**Test ID**:") {
            rest = &rest[pos + 12..];
            if let Some(start) = rest.find('`') {
                if let Some(end) = rest[start + 1..].find('`') {
                    ids.insert(rest[start + 1..start + 1 + end].to_string());
                    rest = &rest[start + 1 + end..];
                    continue;
                }
            }
            break;
        }
    }
    ids
}

fn collect_spec_ids(spec: &Path) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for area in ["rest/unit", "realtime/unit"] {
        let mut files = Vec::new();
        collect_md_files(&spec.join(area), &mut files);
        for file in files {
            let Ok(text) = std::fs::read_to_string(&file) else {
                continue;
            };
            let mut rest = text.as_str();
            while let Some(pos) = rest.find("**Test ID**:") {
                rest = &rest[pos + 12..];
                if let Some(start) = rest.find('`') {
                    if let Some(end) = rest[start + 1..].find('`') {
                        ids.insert(rest[start + 1..start + 1 + end].to_string());
                        rest = &rest[start + 1 + end..];
                        continue;
                    }
                }
                break;
            }
        }
    }
    ids
}

/// All test function names defined in src/ (any `fn name(`).
fn collect_test_fns() -> BTreeSet<String> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_md_files(&src, &mut files); // (no .md in src — reuse walker below)
    let mut fns = BTreeSet::new();
    let Ok(entries) = std::fs::read_dir(&src) else {
        return fns;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "rs") {
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            // Track brace depth: a runnable test fn lives at module level
            // (depth 0 or 1, allowing one `mod tests {}`). An fn nested
            // inside another fn (e.g. swallowed by an unbalanced edit)
            // compiles but never runs — it must NOT count as coverage.
            let mut depth: i32 = 0;
            for line in text.lines() {
                let trimmed = line.trim_start();
                let rest = trimmed
                    .strip_prefix("async fn ")
                    .or_else(|| trimmed.strip_prefix("fn "))
                    .or_else(|| trimmed.strip_prefix("pub fn "))
                    .or_else(|| trimmed.strip_prefix("pub async fn "))
                    .or_else(|| trimmed.strip_prefix("pub(crate) fn "))
                    .or_else(|| trimmed.strip_prefix("pub(crate) async fn "));
                if let Some(rest) = rest {
                    if depth <= 1 {
                        if let Some(paren) = rest.find(['(', '<']) {
                            fns.insert(rest[..paren].trim().to_string());
                        }
                    }
                }
                depth += line.matches('{').count() as i32;
                depth -= line.matches('}').count() as i32;
            }
        }
    }
    fns
}

#[test]
fn uts_coverage_matrix_is_complete() {
    let spec = spec_dir();
    assert!(
        spec.join("rest/unit").is_dir(),
        "UTS spec tree not found at {} — check out the specification repo \
         alongside this one, or set UTS_SPEC_DIR",
        spec.display()
    );
    let spec_ids = collect_spec_ids(&spec);
    assert!(
        spec_ids.len() > 500,
        "implausibly few Test IDs found ({}) — spec tree damaged?",
        spec_ids.len()
    );

    let matrix_text =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("uts_coverage.txt"))
            .expect("uts_coverage.txt missing — run tools/uts_coverage_generate.py");

    let mut mapped: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut excluded: BTreeMap<String, String> = BTreeMap::new();
    let mut problems: Vec<String> = Vec::new();
    let mut excluded_areas: BTreeMap<String, String> = BTreeMap::new();
    for (lineno, line) in matrix_text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("!area ") {
            match rest.split_once(" -- ") {
                Some((area, reason)) if !reason.trim().is_empty() => {
                    excluded_areas.insert(area.trim().to_string(), reason.trim().to_string());
                }
                _ => problems.push(format!(
                    "line {}: `!area` requires `<name> -- <reason>`",
                    lineno + 1
                )),
            }
            continue;
        }
        if let Some((id, fns)) = line.split_once(" => ") {
            mapped.insert(
                id.trim().to_string(),
                fns.split(',').map(|f| f.trim().to_string()).collect(),
            );
        } else if let Some((id, reason)) = line.split_once(" !! ") {
            if reason.trim().is_empty() {
                problems.push(format!("line {}: exclusion without a reason", lineno + 1));
            }
            excluded.insert(id.trim().to_string(), reason.trim().to_string());
        } else {
            problems.push(format!(
                "line {}: unparseable (UNRESOLVED marker left in?): {}",
                lineno + 1,
                line
            ));
        }
    }

    let matrix_ids: BTreeSet<String> = mapped.keys().chain(excluded.keys()).cloned().collect();

    for id in spec_ids.difference(&matrix_ids) {
        problems.push(format!(
            "spec defines {} but the matrix does not account for it",
            id
        ));
    }
    for id in matrix_ids.difference(&spec_ids) {
        problems.push(format!(
            "matrix lists {} but the spec no longer defines it",
            id
        ));
    }

    // CLAUDE.md policy 2: every spec area with Test IDs is dispositioned
    let matrix_ids_all: BTreeSet<String> =
        mapped.keys().chain(excluded.keys()).cloned().collect();
    for area in discover_areas(&spec) {
        if excluded_areas.contains_key(&area) {
            continue;
        }
        let area_ids = collect_area_ids(&spec, &area);
        let untracked = area_ids
            .iter()
            .filter(|id| !matrix_ids_all.contains(*id))
            .count();
        if untracked > 0 {
            problems.push(format!(
                "spec area `{}` has {} Test IDs not in the matrix and no `!area {} -- <reason>` exclusion",
                area, untracked, area
            ));
        }
    }

    let fns = collect_test_fns();
    for (id, mapped_fns) in &mapped {
        for f in mapped_fns {
            if !fns.contains(f) {
                problems.push(format!(
                    "{} maps to `{}` which does not exist in src/",
                    id, f
                ));
            }
        }
    }

    assert!(
        problems.is_empty(),
        "\n\nUTS COVERAGE VIOLATIONS ({}):\n  {}\n\n\
         Every UTS Test ID must be mapped to existing Rust tests or excluded\n\
         with a reason in uts_coverage.txt. Closing a stage means converting\n\
         its exclusions into mappings. See tools/uts_coverage_generate.py.\n",
        problems.len(),
        problems.join("\n  ")
    );
}
