//! Public-surface coverage: rustdoc JSON must match the positive-list allowlists.
//!
//! Stage 3 Runde 8 — a Positivliste is only as good as its coverage of the
//! real surface. This test:
//!
//! 1. Runs `cargo rustdoc -- -Z unstable-options --output-format json` for
//!    `node` and `zkcoins-prover-plonky2` (workspace toolchain is already
//!    nightly).
//! 2. Walks every path reachable from the crate root through **public**
//!    module/item links (including re-export targets for inherent methods
//!    and fields).
//! 3. Diffs the result against the checked-in allowlists under
//!    `tests/public_surface_allowlist_{node,prover}.txt`.
//!
//! **Red on either direction:**
//! - A public path not on the allowlist → surface widened without a list
//!   entry (or without an intentional allowlist update + reason).
//! - An allowlist path missing from the surface → list entry for something
//!   that is no longer public (stale documentation).
//!
//! Allowlist updates are deliberate: edit the `.txt` file in the same
//! change that widens or narrows the surface, with the item-specific
//! reason recorded on the crate-root positive list in `lib.rs`.

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

const NODE_ALLOWLIST: &str = include_str!("public_surface_allowlist_node.txt");
const PROVER_ALLOWLIST: &str = include_str!("public_surface_allowlist_prover.txt");

#[test]
fn node_public_surface_matches_allowlist() {
    let workspace = workspace_root();
    let json_path = rustdoc_json(&workspace, "node");
    let actual = walk_public_paths(&json_path);
    let expected = parse_allowlist(NODE_ALLOWLIST);
    assert_surface_match("node", &actual, &expected);
}

#[test]
fn prover_public_surface_matches_allowlist() {
    let workspace = workspace_root();
    let json_path = rustdoc_json(&workspace, "zkcoins-prover-plonky2");
    let actual = walk_public_paths(&json_path);
    let expected = parse_allowlist(PROVER_ALLOWLIST);
    assert_surface_match("zkcoins-prover-plonky2", &actual, &expected);
}

fn assert_surface_match(label: &str, actual: &BTreeSet<String>, expected: &BTreeSet<String>) {
    let unexpected: Vec<&String> = actual.difference(expected).collect();
    let missing: Vec<&String> = expected.difference(actual).collect();
    if unexpected.is_empty() && missing.is_empty() {
        return;
    }
    let mut msg = format!(
        "{label} public surface drifted from positive-list allowlist\n\
         actual={} paths, allowlist={} paths\n",
        actual.len(),
        expected.len()
    );
    if !unexpected.is_empty() {
        msg.push_str(&format!(
            "\nNEW public paths (not on allowlist — either pub(crate) them \
             or add an item-specific list entry + allowlist line):\n"
        ));
        for p in &unexpected {
            msg.push_str(&format!("  + {p}\n"));
        }
    }
    if !missing.is_empty() {
        msg.push_str(&format!(
            "\nSTALE allowlist paths (no longer public — remove from allowlist \
             and from the crate-root positive list):\n"
        ));
        for p in &missing {
            msg.push_str(&format!("  - {p}\n"));
        }
    }
    panic!("{msg}");
}

fn parse_allowlist(text: &str) -> BTreeSet<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect()
}

fn workspace_root() -> PathBuf {
    // node/tests/… → node/ → workspace
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("node crate parent is workspace root")
        .to_path_buf()
}

fn rustdoc_json(workspace: &Path, package: &str) -> PathBuf {
    let status = Command::new("cargo")
        .current_dir(workspace)
        .args([
            "rustdoc",
            "-p",
            package,
            "--lib",
            "--",
            "-Z",
            "unstable-options",
            "--output-format",
            "json",
        ])
        .status()
        .unwrap_or_else(|e| panic!("failed to spawn cargo rustdoc for {package}: {e}"));
    assert!(
        status.success(),
        "cargo rustdoc -p {package} failed with {status}"
    );

    // rustdoc writes `<crate_name>.json` under target/doc. Package names use
    // hyphens; crate names use underscores.
    let crate_file = package.replace('-', "_");
    let path = workspace
        .join("target/doc")
        .join(format!("{crate_file}.json"));
    assert!(
        path.is_file(),
        "expected rustdoc JSON at {} after documenting {package}",
        path.display()
    );
    path
}

/// Walk every public path reachable from the crate root.
///
/// Re-exports are recorded under the public name and their target type body
/// (fields + inherent methods) is walked under that same public path so
/// `publisher::LegacyBroadcastClient::connect` is covered even when the
/// defining module is `pub(crate)`.
fn walk_public_paths(json_path: &Path) -> BTreeSet<String> {
    let data: Value = serde_json::from_str(
        &std::fs::read_to_string(json_path)
            .unwrap_or_else(|e| panic!("read {}: {e}", json_path.display())),
    )
    .unwrap_or_else(|e| panic!("parse {}: {e}", json_path.display()));

    let index = data
        .get("index")
        .and_then(|v| v.as_object())
        .expect("rustdoc JSON missing index");
    let root = data
        .get("root")
        .and_then(|v| v.as_u64().or_else(|| v.as_i64().map(|i| i as u64)))
        .expect("rustdoc JSON missing root") as u64;

    let mut out = BTreeSet::new();
    walk_item(index, root, &[], &mut out);
    out
}

fn item<'a>(index: &'a serde_json::Map<String, Value>, id: u64) -> Option<&'a Value> {
    index.get(&id.to_string())
}

fn is_public(item: &Value) -> bool {
    item.get("visibility").and_then(|v| v.as_str()) == Some("public")
}

fn item_name(item: &Value) -> Option<&str> {
    item.get("name").and_then(|v| v.as_str())
}

fn inner_kind(item: &Value) -> Option<(&str, &Value)> {
    let inner = item.get("inner")?.as_object()?;
    let (k, v) = inner.iter().next()?;
    Some((k.as_str(), v))
}

fn walk_item(
    index: &serde_json::Map<String, Value>,
    id: u64,
    parts: &[&str],
    out: &mut BTreeSet<String>,
) {
    let Some(it) = item(index, id) else {
        return;
    };
    if !is_public(it) {
        return;
    }
    let Some((kind, body)) = inner_kind(it) else {
        return;
    };

    if kind == "use" {
        let rname = body
            .get("name")
            .and_then(|v| v.as_str())
            .or_else(|| item_name(it));
        let Some(rname) = rname else {
            return;
        };
        let mut new_parts: Vec<&str> = parts.to_vec();
        new_parts.push(rname);
        record(&new_parts, out);
        if let Some(tid) = body.get("id").and_then(|v| v.as_u64()) {
            if let Some(target) = item(index, tid) {
                walk_type_body(index, target, &new_parts, out);
            }
        }
        return;
    }

    let mut new_parts: Vec<&str> = parts.to_vec();
    if let Some(name) = item_name(it) {
        new_parts.push(name);
        record(&new_parts, out);
    }

    match kind {
        "module" => {
            if let Some(items) = body.get("items").and_then(|v| v.as_array()) {
                for child in items {
                    if let Some(cid) = child.as_u64() {
                        walk_item(index, cid, &new_parts, out);
                    }
                }
            }
        }
        _ => walk_type_body(index, it, &new_parts, out),
    }
}

fn walk_type_body(
    index: &serde_json::Map<String, Value>,
    it: &Value,
    parts: &[&str],
    out: &mut BTreeSet<String>,
) {
    let Some((kind, body)) = inner_kind(it) else {
        return;
    };
    match kind {
        "struct" => {
            for fid in struct_field_ids(body) {
                walk_item(index, fid, parts, out);
            }
            if let Some(impls) = body.get("impls").and_then(|v| v.as_array()) {
                for iid in impls {
                    if let Some(id) = iid.as_u64() {
                        walk_impl(index, id, parts, out);
                    }
                }
            }
        }
        "enum" => {
            if let Some(impls) = body.get("impls").and_then(|v| v.as_array()) {
                for iid in impls {
                    if let Some(id) = iid.as_u64() {
                        walk_impl(index, id, parts, out);
                    }
                }
            }
        }
        "trait" => {
            if let Some(items) = body.get("items").and_then(|v| v.as_array()) {
                for tid in items {
                    if let Some(id) = tid.as_u64() {
                        walk_item(index, id, parts, out);
                    }
                }
            }
        }
        _ => {}
    }
}

fn walk_impl(
    index: &serde_json::Map<String, Value>,
    id: u64,
    type_parts: &[&str],
    out: &mut BTreeSet<String>,
) {
    let Some(impl_item) = item(index, id) else {
        return;
    };
    let Some((kind, body)) = inner_kind(impl_item) else {
        return;
    };
    if kind != "impl" {
        return;
    }
    // Inherent impls only — trait methods are not free names on our surface.
    if !body.get("trait").map(|t| t.is_null()).unwrap_or(true) {
        // trait field present and non-null → trait impl
        if body.get("trait").is_some() && !body.get("trait").unwrap().is_null() {
            return;
        }
    }
    // serde_json: missing vs null — rustdoc uses null for inherent
    if let Some(t) = body.get("trait") {
        if !t.is_null() {
            return;
        }
    }
    if let Some(items) = body.get("items").and_then(|v| v.as_array()) {
        for mid in items {
            if let Some(id) = mid.as_u64() {
                walk_item(index, id, type_parts, out);
            }
        }
    }
}

fn struct_field_ids(body: &Value) -> Vec<u64> {
    let kind = match body.get("kind") {
        Some(k) => k,
        None => {
            return body
                .get("fields")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_u64()).collect())
                .unwrap_or_default()
        }
    };
    if let Some(plain) = kind.get("plain") {
        return plain
            .get("fields")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_u64()).collect())
            .unwrap_or_default();
    }
    if let Some(tuple) = kind.get("tuple") {
        return tuple
            .as_array()
            .map(|a| a.iter().filter_map(|x| x.as_u64()).collect())
            .unwrap_or_default();
    }
    Vec::new()
}

fn record(parts: &[&str], out: &mut BTreeSet<String>) {
    if parts.len() <= 1 {
        return;
    }
    out.insert(parts.join("::"));
}
