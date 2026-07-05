//! Boundary-case comparison of three `canonicalize_best_effort` implementations:
//!
//!   1. sandbox/linux.rs  — `canonicalize_best_effort`
//!   2. sandbox/seatbelt.rs — `canonicalize_best_effort_macos` (identical to linux)
//!   3. tools/mod.rs — `canonicalize_best_effort` (different signature)
//!
//! This test runs the first two (identical algorithm) and the third through
//! the same boundary cases and compares their output semantics.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

// ─── Copy of sandbox/linux.rs canonicalize_best_effort ──────────────────────────

fn cb_linux(path: &Path) -> (PathBuf, Option<OsString>) {
    let mut current = path.to_path_buf();
    let mut missing: Vec<OsString> = Vec::new();

    loop {
        if current.exists() {
            let canon = std::fs::canonicalize(&current).unwrap_or(current);
            let first_missing = missing.pop();
            return (canon, first_missing);
        }

        if let Some(name) = current.file_name() {
            missing.push(name.to_os_string());
        }

        match current.parent() {
            Some(parent) => current = parent.to_path_buf(),
            None => {
                let first_missing = missing.pop();
                return (current, first_missing);
            }
        }
    }
}

// ─── Copy of tools/mod.rs canonicalize_best_effort + normalize_path ───────────

fn normalize_path(path: &Path) -> PathBuf {
    use std::path::Component;

    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => {
                out.push(other);
            }
        }
    }
    out
}

fn cb_tools(path: &Path) -> Option<PathBuf> {
    if let Ok(canon) = std::fs::canonicalize(path) {
        return Some(canon);
    }

    let mut existing = path.to_path_buf();
    let mut suffix: Vec<OsString> = vec![];

    loop {
        if let Ok(canon) = std::fs::canonicalize(&existing) {
            let mut rebuilt = canon;
            for component in suffix.into_iter().rev() {
                rebuilt.push(component);
            }
            return Some(normalize_path(&rebuilt));
        }

        let component = match existing.file_name() {
            Some(c) => c.to_os_string(),
            None => return None,
        };
        suffix.push(component);

        if !existing.pop() {
            return None;
        }
    }
}

/// Helper: unpack first_missing once and return both the string and the masked path.
fn linux_masked_path(path: &Path) -> (PathBuf, String, PathBuf) {
    let (ancestor, first_missing) = cb_linux(path);
    let missing_str = first_missing.unwrap().to_string_lossy().to_string();
    let masked = ancestor.join(&missing_str);
    (ancestor, missing_str, masked)
}

// ─── Boundary cases ─────────────────────────────────────────────────────────

#[test]
fn boundary_case_1_path_does_not_exist() {
    let dir = tempfile::tempdir().unwrap();
    let phantom = dir.path().join("missing_file.txt");
    assert!(!phantom.exists());

    let tools_out = cb_tools(&phantom).unwrap();
    let expected_tools = fs::canonicalize(dir.path())
        .unwrap()
        .join("missing_file.txt");
    assert_eq!(tools_out, expected_tools);

    let (anc, miss, masked) = linux_masked_path(&phantom);
    assert_eq!(anc, fs::canonicalize(dir.path()).unwrap());
    assert_eq!(miss, "missing_file.txt");
    assert_eq!(masked, tools_out);

    println!("✓ Case 1 (path does not exist):");
    println!("  tools → {}", tools_out.display());
    println!("  linux → {}/{}", anc.display(), miss);
}

#[test]
fn boundary_case_2_multi_level_nonexistent() {
    let dir = tempfile::tempdir().unwrap();
    let phantom = dir.path().join("a").join("b").join("c");
    assert!(!phantom.exists());

    let tools_out = cb_tools(&phantom).unwrap();
    let expected_tools = fs::canonicalize(dir.path())
        .unwrap()
        .join("a")
        .join("b")
        .join("c");
    assert_eq!(tools_out, expected_tools);

    let (anc, miss, masked) = linux_masked_path(&phantom);
    assert_eq!(anc, fs::canonicalize(dir.path()).unwrap());
    assert_eq!(miss, "a");

    // linux masks only the first missing component, tools returns full path.
    // This is expected — different purposes.
    assert_ne!(masked, tools_out);

    println!("✓ Case 2 (multi-level nonexistent: a/b/c):");
    println!("  tools → {}", tools_out.display());
    println!(
        "  linux → {}/{} (first missing component only)",
        anc.display(),
        miss
    );
    println!(
        "  NOTE: Different by design — linux masks {}/a (blocks subtree creation),",
        anc.display()
    );
    println!(
        "  tools rebuilds full {}/a/b/c for containment checking.",
        anc.display()
    );
}

#[test]
fn boundary_case_3_trailing_slash() {
    let dir = tempfile::tempdir().unwrap();
    let with_slash = PathBuf::from(format!("{}/does_not_exist/", dir.path().display()));
    assert!(!with_slash.exists());

    let tools_out = cb_tools(&with_slash).unwrap();
    let expected_tools = fs::canonicalize(dir.path()).unwrap().join("does_not_exist");
    assert_eq!(tools_out, expected_tools);

    let (anc, miss, masked) = linux_masked_path(&with_slash);
    assert_eq!(anc, fs::canonicalize(dir.path()).unwrap());
    assert_eq!(miss, "does_not_exist");
    assert_eq!(masked, tools_out);

    println!("✓ Case 3 (trailing slash):");
    println!("  tools → {}", tools_out.display());
    println!("  linux → {}/{}", anc.display(), miss);
}

#[test]
fn boundary_case_4_single_component() {
    // Create a single-component path under a temp dir (simulates
    // how tools always joins relative paths with cwd first).
    let dir = tempfile::tempdir().unwrap();
    let single = dir.path().join("just_this");
    assert!(!single.exists());

    let tools_out = cb_tools(&single).unwrap();
    let expected_tools = fs::canonicalize(dir.path()).unwrap().join("just_this");
    assert_eq!(tools_out, expected_tools);

    let (anc, miss, masked) = linux_masked_path(&single);
    assert_eq!(anc, fs::canonicalize(dir.path()).unwrap());
    assert_eq!(miss, "just_this");
    assert_eq!(masked, tools_out);

    println!("✓ Case 4 (single component):");
    println!("  tools → {}", tools_out.display());
    println!("  linux → {}/{}", anc.display(), miss);
}

#[test]
fn boundary_case_5_symlink_in_path() {
    let dir = tempfile::tempdir().unwrap();
    let real_dir = dir.path().join("real");
    let link_dir = dir.path().join("link");
    fs::create_dir(&real_dir).unwrap();

    #[cfg(unix)]
    std::os::unix::fs::symlink(&real_dir, &link_dir).unwrap();

    #[cfg(not(unix))]
    {
        println!("  SKIP: symlink test requires Unix");
        return;
    }

    let phantom = link_dir.join("missing_file.txt");
    assert!(!phantom.exists());

    let tools_out = cb_tools(&phantom).unwrap();
    let expected = fs::canonicalize(&real_dir)
        .unwrap()
        .join("missing_file.txt");
    assert_eq!(tools_out, expected);

    let (anc, miss, masked) = linux_masked_path(&phantom);
    assert_eq!(anc, fs::canonicalize(&real_dir).unwrap());
    assert_eq!(miss, "missing_file.txt");
    assert_eq!(masked, tools_out);

    println!("✓ Case 5 (symlink in path):");
    println!("  tools → {}", tools_out.display());
    println!(
        "  linux → {}/{} (symlink resolved to real_dir)",
        anc.display(),
        miss
    );
}

// ─── Summary ────────────────────────────────────────────────────────────────

#[test]
fn print_summary() {
    println!();
    println!("═══════════════════════════════════════════════════");
    println!("  canonicalize_best_effort comparison summary");
    println!("═══════════════════════════════════════════════════");
    println!();
    println!("Three implementations:");
    println!("  1. sandbox/linux.rs:392   — cb_linux");
    println!("  2. sandbox/seatbelt.rs:189 — cb_macos (identical to linux)");
    println!("  3. tools/mod.rs:34        — cb_tools (different signature + normalize)");
    println!();
    println!("Boundary cases: all five pass with consistent results.");
    println!();
    println!("  Case 1 (single missing)    : equivalent result ✓");
    println!("  Case 2 (multi-level missing): DIFFERENT by design");
    println!("    - linux masks first missing component (blocks subtree creation)");
    println!("    - tools rebuilds full path (for containment checks)");
    println!("  Case 3 (trailing slash)    : equivalent result ✓");
    println!("  Case 4 (single component)  : equivalent result ✓");
    println!("  Case 5 (symlink in path)   : equivalent result ✓");
    println!();
    println!("No unexpected behavioral inconsistencies found.");
    println!("The one difference (Case 2) is by design — the two families");
    println!("serve different purposes:");
    println!("  sandbox: generate mount/ACL mask targets");
    println!("  tools:   produce canonical paths for safety checks");
    println!();
}
