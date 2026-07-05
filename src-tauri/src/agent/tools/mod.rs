//! File I/O tools (read, write, edit) for the MaoMaoChat agent.
//!
//! These tools operate directly on the filesystem via std::fs. They do NOT go
//! through the sandbox — unlike bash/python tools. Therefore they must perform
//! their own path containment and protected-path checks.
//!
//! Shared path validation lives here so all three tools reuse the same logic.

#![allow(dead_code)]

pub mod bash;
pub mod edit;
pub mod read;
pub mod write;

use std::path::{Path, PathBuf};

use crate::agent::types::ToolError;

/// Walk up from `path` until we find an ancestor that can be canonicalized,
/// then rebuild the remaining suffix on top of it, and finally normalize
/// `..` / `.` components out of the rebuilt path.
///
/// This handles the case where the target file and some of its parent dirs
/// don't exist yet (e.g. writing to `a/b/c/new.md` when `a/b/c/` doesn't
/// exist). The walk stops at the first existing ancestor, canonicalizes it
/// (resolving symlinks / `..` along the existing portion), then appends the
/// remaining non-existent components verbatim.
///
/// **Normalization is mandatory**: the suffix may contain `..` components
/// that, if left un-collapsed, would fool the downstream `starts_with`
/// containment check (a `Path`-based component prefix match would see
/// `/ws/newdir/../../etc` as starting with `/ws`, missing the escape).
fn canonicalize_best_effort(path: &Path, raw: &str) -> Result<PathBuf, ToolError> {
    // If the path itself exists, just canonicalize it.
    if let Ok(canon) = std::fs::canonicalize(path) {
        return Ok(canon);
    }

    // Walk up to find the first existing ancestor.
    let mut existing = path.to_path_buf();
    let mut suffix: Vec<std::ffi::OsString> = vec![];

    loop {
        if let Ok(canon) = std::fs::canonicalize(&existing) {
            // Rebuild: canonical_base / suffix... / filename
            let mut rebuilt = canon;
            for component in suffix.into_iter().rev() {
                rebuilt.push(component);
            }
            // Collapse `..` / `.` in the non-existent suffix so that
            // a path like `cwd/newdir/../../etc` collapses to `cwd/etc`
            // before the containment check.
            return Ok(normalize_path(&rebuilt));
        }

        // Pop one component and try again.
        let component = existing
            .file_name()
            .map(|c| c.to_os_string())
            .ok_or_else(|| ToolError::NotFound(format!("cannot resolve path: {}", raw)))?;
        suffix.push(component);

        if !existing.pop() {
            // We hit the root and still nothing canonicalized — the cwd itself
            // may not exist, which is a configuration error.
            return Err(ToolError::NotFound(format!(
                "no canonicalizable ancestor found for: {}",
                raw
            )));
        }
    }
}

/// Normalize a path by collapsing `..` and `.` components using pure
/// lexical processing (no filesystem access).
///
/// This is necessary when `canonicalize_best_effort` rebuilds a path from
/// an existing ancestor + a non-existent suffix — the suffix may contain
/// `..` that would escape the workspace boundary.
fn normalize_path(path: &Path) -> PathBuf {
    use std::path::Component;

    let mut stack: Vec<std::ffi::OsString> = Vec::new();

    for component in path.components() {
        match component {
            Component::ParentDir => {
                // Pop unless the stack is empty (root-relative `..` stays).
                // We never pop past the canonicalized base, so a suffix
                // like `../../etc` that tries to escape past cwd will leave
                // `etc` in the stack after popping the nonexistent ancestors,
                // and the containment check will catch it.
                stack.pop();
            }
            Component::CurDir => {
                // Skip `.` entirely.
            }
            other => {
                stack.push(other.as_os_str().to_os_string());
            }
        }
    }

    let mut result = PathBuf::new();
    for comp in stack {
        result.push(comp);
    }
    result
}

/// Canonicalize a raw path (relative to `cwd`) and enforce two security checks:
///
/// **Known limitation — TOCTOU**: The `canonicalize()` check and the
/// subsequent `fs::read` / `fs::write` are not atomic. If a directory
/// component is replaced with a symlink between the check and the I/O
/// operation (e.g. by a concurrently-running `bash` tool), the containment
/// result may be stale. This is acceptable for a single-user desktop
/// assistant; hardening (e.g. `openat` + `O_NOFOLLOW`) can be added later
/// if the threat model changes.
///
/// 1. **Containment** — the resolved path MUST be a descendant of `cwd`.
///    `canonicalize()` resolves all `..` and symlinks, so path-traversal
///    payloads like `../../etc/passwd` are caught here.
///    Violations return `ToolError::NotFound`.
///
/// 2. **Protected paths** — the resolved path MUST NOT start with any
///    `protected_paths` prefix (e.g. `.git`, `.agents`). Protected paths are
///    resolved relative to `cwd`; if a protected path does not exist yet,
///    its joined (non-canonical) form is used for the prefix check, so that
///    creating a file inside a not-yet-existing protected directory is also
///    blocked.
///    Violations return `ToolError::SandboxDenied`.
///
/// `must_exist`: if `true`, the path is canonicalized directly (file must
/// exist — used by read and edit). If `false`, canonicalization is attempted
/// on the file first and falls back to the parent directory (used by write
/// for new files).
pub fn validate_path(
    raw: &str,
    cwd: &Path,
    protected_paths: &[PathBuf],
    must_exist: bool,
) -> Result<PathBuf, ToolError> {
    let cwd_canon = std::fs::canonicalize(cwd).map_err(ToolError::Io)?;

    // Resolve raw → absolute path
    let joined = if Path::new(raw).is_absolute() {
        PathBuf::from(raw)
    } else {
        cwd_canon.join(raw)
    };

    // Canonicalize (resolves `..`, symlinks, etc.)
    let canon = if must_exist {
        // File must exist — canonicalize directly.
        std::fs::canonicalize(&joined).map_err(|e| {
            ToolError::NotFound(format!("path not found or inaccessible: {} ({})", raw, e))
        })?
    } else {
        // File may not exist (write tool). Walk up from the target until we
        // find a canonicalizable ancestor, then rebuild the suffix from it.
        canonicalize_best_effort(&joined, raw)?
    };

    // ── Check 1: containment ──
    if !canon.starts_with(&cwd_canon) {
        return Err(ToolError::NotFound(format!(
            "path escapes workspace boundary: '{}' resolves outside cwd",
            raw
        )));
    }

    // ── Check 2: protected paths ──
    for prot in protected_paths {
        let prot_resolved = if prot.is_absolute() {
            prot.clone()
        } else {
            cwd_canon.join(prot)
        };
        // If the protected path itself exists, use its canonical form for the
        // prefix check (catches symlink tricks). Otherwise use the raw joined
        // form (catches attempts to create files under not-yet-existing
        // protected directories, e.g. writing .git/config when .git/ does not
        // yet exist).
        let prot_check = std::fs::canonicalize(&prot_resolved).unwrap_or(prot_resolved);
        if canon.starts_with(&prot_check) {
            return Err(ToolError::SandboxDenied(format!(
                "path is protected: '{}' (blocked by protected path '{}')",
                raw,
                prot.display(),
            )));
        }
    }

    Ok(canon)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Helper: create a temp workspace with a predictable structure.
    fn setup_workspace() -> (tempfile::TempDir, Vec<PathBuf>) {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();

        // Create some files
        fs::write(ws.join("hello.txt"), "hello world\n").unwrap();
        fs::create_dir_all(ws.join("sub")).unwrap();
        fs::write(ws.join("sub/note.md"), "# Note\ncontent\n").unwrap();

        // Create a .git dir (protected)
        fs::create_dir_all(ws.join(".git")).unwrap();
        fs::write(ws.join(".git/config"), "[core]\n").unwrap();

        // Create a symlink test: a symlink pointing outside
        // (skip on Windows where symlinks need admin)
        #[cfg(unix)]
        {
            let _ = std::os::unix::fs::symlink("/etc/passwd", ws.join("escape_link"));
        }

        let protected = vec![PathBuf::from(".git"), PathBuf::from(".agents")];

        (dir, protected)
    }

    #[test]
    fn test_validate_path_normal_file() {
        let (dir, protected) = setup_workspace();
        let ws = dir.path();

        let canon = validate_path("hello.txt", ws, &protected, true).unwrap();
        assert_eq!(canon, ws.canonicalize().unwrap().join("hello.txt"));
    }

    #[test]
    fn test_validate_path_subdir() {
        let (dir, protected) = setup_workspace();
        let ws = dir.path();

        let canon = validate_path("sub/note.md", ws, &protected, true).unwrap();
        assert_eq!(canon, ws.canonicalize().unwrap().join("sub/note.md"));
    }

    #[test]
    fn test_validate_path_escape_with_dotdot() {
        let (dir, protected) = setup_workspace();
        let ws = dir.path();

        // Attempt to escape using ../
        let result = validate_path("../../etc/passwd", ws, &protected, true);
        assert!(matches!(result, Err(ToolError::NotFound(_))));
    }

    #[test]
    fn test_validate_path_protected_dir() {
        let (dir, protected) = setup_workspace();
        let ws = dir.path();

        // Trying to read an existing protected file
        let result = validate_path(".git/config", ws, &protected, true);
        assert!(matches!(result, Err(ToolError::SandboxDenied(_))));
    }

    #[test]
    fn test_validate_path_write_to_protected() {
        let (dir, protected) = setup_workspace();
        let ws = dir.path();

        // Trying to write a new file under a protected dir (must_exist=false)
        let result = validate_path(".git/hooks/pre-commit", ws, &protected, false);
        assert!(matches!(result, Err(ToolError::SandboxDenied(_))));
    }

    #[test]
    fn test_validate_path_absolute_inside_workspace() {
        let (dir, protected) = setup_workspace();
        let ws = dir.path();
        let ws_canon = ws.canonicalize().unwrap();

        // Pass an absolute path that is inside the workspace
        let abs_path = ws_canon.join("hello.txt").to_string_lossy().to_string();
        let canon = validate_path(&abs_path, ws, &protected, true).unwrap();
        assert_eq!(canon, ws_canon.join("hello.txt"));
    }

    #[test]
    fn test_validate_path_write_new_file() {
        let (dir, protected) = setup_workspace();
        let ws = dir.path();
        let ws_canon = ws.canonicalize().unwrap();

        // Write to a file that doesn't exist yet (must_exist=false)
        let canon = validate_path("brand_new.md", ws, &protected, false).unwrap();
        assert_eq!(canon, ws_canon.join("brand_new.md"));
        assert!(!canon.exists()); // validate_path should NOT create the file
    }

    #[test]
    fn test_validate_path_write_escape_with_dotdot() {
        // Write a non-existent path that uses `..` to escape.
        // `newdir` does NOT exist, so this hits canonicalize_best_effort.
        // After the walk-up, the suffix `newdir/../../etc/evil.txt` must
        // be normalized so that the containment check sees the escaped
        // path and rejects it.
        let (dir, protected) = setup_workspace();
        let ws = dir.path();

        let result = validate_path("newdir/../../etc/evil.txt", ws, &protected, false);
        match result {
            Err(ToolError::NotFound(_)) => {} // expected
            Ok(p) => panic!("unexpectedly allowed escape: {:?}", p),
            other => panic!("expected NotFound, got {:?}", other),
        }
    }

    #[test]
    fn test_normalize_path_collapses_dotdot() {
        // Simple dotdot
        assert_eq!(
            normalize_path(Path::new("/foo/bar/../baz")),
            PathBuf::from("/foo/baz")
        );
        // Multiple dotdots
        assert_eq!(
            normalize_path(Path::new("/foo/bar/../../baz")),
            PathBuf::from("/baz")
        );
        // Dot
        assert_eq!(
            normalize_path(Path::new("/foo/./bar")),
            PathBuf::from("/foo/bar")
        );
        // Dotdot deeper than root: since our implementation doesn't
        // special-case the filesystem root, popping past it produces a
        // relative path. This is fine for our use case because
        // normalize_path is always called on paths built from an absolute
        // canonical base, and if `..` pops past the cwd the downstream
        // `starts_with(cwd_canon)` containment check will catch it.
        assert_eq!(normalize_path(Path::new("/x/../../y")), PathBuf::from("y"));
    }

    #[cfg(unix)]
    #[test]
    fn test_validate_path_symlink_escape() {
        let (dir, protected) = setup_workspace();
        let ws = dir.path();

        // The symlink points to /etc/passwd, canonicalize resolves it.
        // containment check should catch this.
        let result = validate_path("escape_link", ws, &protected, true);
        assert!(matches!(result, Err(ToolError::NotFound(_))));
    }
}
