//! macOS sandbox via `/usr/bin/sandbox-exec` + dynamically generated SBPL.
//!
//! Generates a Sandbox Profile Language (SBPL) string at runtime — no `.sb` files
//! on disk.  Policy mapping:
//!
//! | Policy field          | SBPL rules                                                     |
//! |-----------------------|----------------------------------------------------------------|
//! | `writable_roots`      | `(allow file-read* file-write* (subpath "<path>"))`           |
//! | `protected_paths`     | `(deny file-read* file-write* (subpath "<canon-path>"))`       |
//! | `network == Isolated` | `(deny network*)`                                              |
//! | `mode == ReadOnly`    | no `file-write*` rules at all                                  |
//! | `mode == DangerFullAccess` | no rules — sandbox-exec with empty profile               |
//!
//! # Symlink hardening (post red-team audit)
//!
//! Apple's SBPL `subpath` operator follows symlinks during enforcement.
//! However, to be safe we:
//! 1. Canonicalize (resolve symlinks) every protected_path before embedding
//!    it in the SBPL string.  This ensures the deny rule applies to the REAL
//!    path, not the symlink path, even if the symlink itself changes later.
//! 2. For non-existent protected paths, walk up to the first existing
//!    ancestor, resolve that, and mask the first non-existent component.
//! 3. Protected paths deny BOTH `file-read*` and `file-write*` (not just
//!    writes) — same threat model as Linux: an agent reading sensitive files
//!    under a protected path and sending them to the LLM is data exfiltration.
//!
//! # Known limitation: global read isolation
//!
//! Unlike the Linux bwrap implementation (which selectively bind-mounts only
//! needed /etc files), seatbelt's SBPL defaults to `(allow default)` which
//! permits reads everywhere.  Tightening this to a global `(deny file-read*)`
//! with selective allows is possible but significantly more complex — SBPL
//! requires explicit allow rules for every shared library, system config file,
//! and resource the sandboxed process may touch.  For macOS we rely on the
//! combination of protected_paths + writable_roots boundaries; system files
//! like /etc/passwd that fall outside writable_roots are treated as a
//! separate hardening milestone.

use std::path::{Path, PathBuf};

use crate::agent::types::{NetworkPolicy, SandboxMode, SandboxPolicy, ToolError};

/// Guard that keeps the SBPL profile temp file alive for the child process lifetime.
/// On drop, the temp file is removed.
pub struct SeatbeltGuard {
    _profile: Option<tempfile::NamedTempFile>,
}

/// Build a `std::process::Command` that runs `command` via `sandbox-exec`.
/// Returns the command and a guard that must live for the child's lifetime.
pub fn build_sandboxed_command(
    command: &str,
    cwd: &Path,
    policy: &SandboxPolicy,
) -> Result<(std::process::Command, SeatbeltGuard), ToolError> {
    if matches!(policy.mode, SandboxMode::DangerFullAccess) {
        // No sandbox — spawn directly (same as LocalExecutor).
        let mut cmd = std::process::Command::new("sh");
        cmd.arg("-c")
            .arg(command)
            .current_dir(cwd)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        return Ok((cmd, SeatbeltGuard { _profile: None }));
    }

    let profile = build_profile(cwd, policy)?;

    // Write SBPL to a temporary file that sandbox-exec will read.
    // The NamedTempFile wrapper is returned to the caller as a guard —
    // it lives for the child process's entire lifetime and is cleaned up
    // on drop when the child exits.
    let mut tmp = tempfile::NamedTempFile::new().map_err(|e| ToolError::Io(e))?;
    std::io::Write::write_all(&mut tmp, profile.as_bytes()).map_err(|e| ToolError::Io(e))?;
    let profile_path = tmp.path().to_string_lossy().to_string();

    let mut cmd = std::process::Command::new("/usr/bin/sandbox-exec");
    cmd.arg("-f")
        .arg(&profile_path)
        .arg("sh")
        .arg("-c")
        .arg(command)
        .current_dir(cwd)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    Ok((cmd, SeatbeltGuard { _profile: Some(tmp) }))
}

/// Build a complete SBPL (version 1) string from policy.
fn build_profile(cwd: &Path, policy: &SandboxPolicy) -> Result<String, ToolError> {
    let mut sb = String::new();

    // ── SBPL header ──
    sb.push_str("(version 1)\n");

    // ── Always allow basic process operations ──
    sb.push_str("(allow default)\n");

    // ── Deny all writes by default, then selectively allow ──
    sb.push_str("(deny file-write*)\n");

    // ── Network policy ──
    match policy.network {
        NetworkPolicy::Isolated => {
            sb.push_str("(deny network*)\n");
        }
        NetworkPolicy::ProxyOnly => {
            // Allow localhost but deny external — SBPL doesn't have
            // fine-grained per-address network rules (that's a PF-level
            // concern).  We emit a best-effort restriction.
            sb.push_str("(allow network* (local ip \"localhost\"))\n");
            sb.push_str("(allow network* (local ip \"127.0.0.1\"))\n");
            sb.push_str("(deny network*)\n");
        }
        NetworkPolicy::FullAccess => {
            // No network restrictions — the (allow default) above covers it.
        }
    }

    // ── Writable roots ──
    if matches!(policy.mode, SandboxMode::WorkspaceWrite) {
        for root in &policy.writable_roots {
            let resolved = if root.is_absolute() {
                root.clone()
            } else {
                cwd.join(root)
            };
            // Canonicalize so that the subpath in the profile is absolute.
            let canon = std::fs::canonicalize(&resolved).unwrap_or(resolved);
            let abs = canon.to_string_lossy();
            sb.push_str(&format!(
                "(allow file-read* file-write* (subpath \"{}\"))\n",
                escape_sbpl(&abs),
            ));
        }
    }

    // ── Protected paths (deny reads AND writes — overrides writable_roots) ──
    //
    // Each protected_path is canonicalized (symlinks resolved) and then
    // embedded as a deny rule.  If the path does not exist, we use
    // canonicalize_best_effort to find the first non-existent component
    // and deny access there — preventing creation of the protected path.
    for prot in &policy.protected_paths {
        let resolved = if prot.is_absolute() {
            prot.clone()
        } else {
            cwd.join(prot)
        };

        // Try full canonicalization first (resolves symlinks).
        if let Ok(canon) = std::fs::canonicalize(&resolved) {
            let abs = canon.to_string_lossy();
            sb.push_str(&format!(
                "(deny file-read* file-write* (subpath \"{}\"))\n",
                escape_sbpl(&abs),
            ));
        } else {
            // Path does not exist — walk up to find first existing ancestor.
            let (ancestor, first_missing) = canonicalize_best_effort_macos(&resolved);
            if let Some(name) = first_missing {
                let mask_target = ancestor.join(&name);
                let abs = mask_target.to_string_lossy();
                sb.push_str(&format!(
                    "(deny file-read* file-write* (subpath \"{}\"))\n",
                    escape_sbpl(&abs),
                ));
            } else {
                // Even if ancestor is root or unclear, deny the raw path.
                let abs = ancestor.to_string_lossy();
                sb.push_str(&format!(
                    "(deny file-read* file-write* (subpath \"{}\"))\n",
                    escape_sbpl(&abs),
                ));
            }
        }
    }

    Ok(sb)
}

/// Escape a path string for embedding in SBPL double-quoted strings.
/// Only backslash and double-quote need escaping in SBPL.
fn escape_sbpl(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Canonicalize a path on a best-effort basis (macOS edition — mirrors
/// `canonicalize_best_effort` in linux.rs).
///
/// Returns `(existing_canonical_ancestor, first_nonexistent_component_name)`.
fn canonicalize_best_effort_macos(path: &Path) -> (PathBuf, Option<std::ffi::OsString>) {
    let mut current = path.to_path_buf();
    let mut missing: Vec<std::ffi::OsString> = Vec::new();

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

// ─── Tests ───────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_build_profile_isolated_network() {
        let policy = SandboxPolicy {
            mode: SandboxMode::ReadOnly,
            writable_roots: vec![],
            network: NetworkPolicy::Isolated,
            protected_paths: vec![],
        };
        let dir = tempfile::tempdir().unwrap();
        let profile = build_profile(dir.path(), &policy).unwrap();
        assert!(profile.contains("(deny network*)"), "profile:\n{}", profile);
        assert!(profile.contains("(deny file-write*)"), "profile:\n{}", profile);
    }

    #[test]
    fn test_build_profile_writable_roots() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("data");
        fs::create_dir_all(&sub).unwrap();

        let policy = SandboxPolicy {
            mode: SandboxMode::WorkspaceWrite,
            writable_roots: vec![sub.clone()],
            network: NetworkPolicy::FullAccess,
            protected_paths: vec![],
        };
        let profile = build_profile(dir.path(), &policy).unwrap();
        assert!(
            profile.contains("file-write*"),
            "should allow writes, profile:\n{}",
            profile
        );
    }

    #[test]
    fn test_build_profile_protected_paths_override() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();
        let prot = ws.join(".git");
        fs::create_dir_all(&prot).unwrap();

        let policy = SandboxPolicy {
            mode: SandboxMode::WorkspaceWrite,
            writable_roots: vec![ws.to_path_buf()],
            network: NetworkPolicy::FullAccess,
            protected_paths: vec![PathBuf::from(".git")],
        };
        let profile = build_profile(ws, &policy).unwrap();
        // Protected .git must appear as a deny (now file-read* file-write*)
        // AFTER the workspace allow.
        let git_deny_pos =
            profile.find("(deny file-read* file-write* (subpath").unwrap();
        let ws_allow_pos =
            profile.find("(allow file-read* file-write* (subpath").unwrap();
        assert!(
            git_deny_pos > ws_allow_pos,
            "protected deny must come after writable allow:\n{}",
            profile
        );
        // Also verify it denies reads, not just writes.
        assert!(
            profile.contains("file-read* file-write*"),
            "protected deny must include file-read*:\n{}",
            profile
        );
    }

    #[test]
    fn test_canonicalize_best_effort_macos_existing() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("real_file.txt");
        fs::write(&file, "data").unwrap();

        let (ancestor, first_missing) = canonicalize_best_effort_macos(&file);
        assert!(first_missing.is_none(), "existing path should have no missing component");
        assert_eq!(ancestor, std::fs::canonicalize(&file).unwrap());
    }

    #[test]
    fn test_canonicalize_best_effort_macos_nonexistent() {
        let dir = tempfile::tempdir().unwrap();
        let phantom = dir.path().join("does_not_exist");
        assert!(!phantom.exists());

        let (ancestor, first_missing) = canonicalize_best_effort_macos(&phantom);
        assert!(first_missing.is_some(), "non-existent path should have missing component");
        assert_eq!(first_missing.unwrap(), "does_not_exist");
        assert_eq!(ancestor, std::fs::canonicalize(dir.path()).unwrap());
    }
}
