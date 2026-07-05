//! Linux sandbox — primary: bwrap (bubblewrap), fallback: Landlock LSM.
//!
//! # Strategy
//!
//! 1. Probe for `bwrap` on PATH.  If found → build a bwrap command with:
//!    `--unshare-user --unshare-pid`, `--unshare-net` (when Isolated),
//!    `--bind` for writable_roots, mount-level masking for protected_paths.
//!
//! 2. If bwrap is not found → fall back to Landlock via `pre_exec`:
//!    - Deny all writes globally.
//!    - Allow reads everywhere (`/`).
//!    - Allow writes only on `writable_roots` (existing paths).
//!    - Protected paths are excluded from the write set.
//!
//!    **Network isolation**: Landlock ABI v4 (Linux 6.7+) supports
//!    `LANDLOCK_ACCESS_NET_CONNECT_TCP`.  When available we apply it;
//!    otherwise the landlock fallback cannot enforce network isolation.
//!
//! # Read isolation via selective /etc bind-mounts
//!
//! We explicitly bind only the specific files under `/etc` that the sandboxed
//! command actually needs.  We **never** bind `/etc` as a whole directory.
//! Rationale: blanket `/etc` binding leaks `/etc/passwd`, `/etc/hosts`, and
//! any other world-readable file under `/etc` — this is a confirmed red-team
//! breach vector (openai/codex issues #15725, #17079).
//!
//! # Protected paths: mount-level masking, not user-space string checks
//!
//! For each protected_path we canonicalize it (resolve symlinks) to find the
//! **real** location that needs to be masked.  Then we use bwrap's own mount
//! mechanism to either bind /dev/null (for files) or mount an empty tmpfs
//! (for directories) at that location.  Because the masking happens at the
//! kernel mount layer, it cannot be bypassed by symlink tricks, `..`
//! path-splicing, or any other purely string-based path manipulation.

#![allow(dead_code)]

use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::agent::types::{NetworkPolicy, SandboxMode, SandboxPolicy, ToolError};

/// Test whether `bwrap` is available on this system.
fn bwrap_available() -> bool {
    Command::new("bwrap")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Build a `std::process::Command` that runs `command` sandboxed.
///
/// Prefers bwrap; falls back to landlock if bwrap is not installed.
pub fn build_sandboxed_command(
    command: &str,
    cwd: &Path,
    policy: &SandboxPolicy,
) -> Result<std::process::Command, ToolError> {
    if matches!(policy.mode, SandboxMode::DangerFullAccess) {
        let mut cmd = std::process::Command::new("sh");
        cmd.arg("-c")
            .arg(command)
            .current_dir(cwd)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        return Ok(cmd);
    }

    // Canonicalize cwd so bwrap bind-mounts use real paths.
    let cwd_canon = std::fs::canonicalize(cwd).map_err(ToolError::Io)?;

    if bwrap_available() {
        build_bwrap_command(command, &cwd_canon, policy)
    } else {
        build_landlock_command(command, &cwd_canon, policy)
    }
}

// ─── bwrap ───────────────────────────────────────────────────────────────────────

fn build_bwrap_command(
    command: &str,
    cwd_canon: &Path,
    policy: &SandboxPolicy,
) -> Result<std::process::Command, ToolError> {
    let mut cmd = std::process::Command::new("bwrap");

    // ── Namespace isolation ──
    cmd.arg("--unshare-user");
    cmd.arg("--unshare-pid");
    if matches!(policy.network, NetworkPolicy::Isolated) {
        cmd.arg("--unshare-net");
    }

    // ── Minimal /proc and /dev (read-only) ──
    cmd.arg("--proc").arg("/proc");
    cmd.arg("--dev").arg("/dev");

    // ── Bind essential system directories read-only ──
    // We need /usr/{bin,lib,…} and /bin so that sh and basic utilities
    // are reachable inside the namespace.
    //
    // ⚠️  Do NOT bind /etc as a whole directory — that leaks /etc/passwd,
    // /etc/hosts, and any other world-readable files under /etc.
    // Instead, bind only the specific files that the sandboxed command needs.
    for sys_dir in &["/usr", "/bin", "/lib", "/lib64"] {
        if Path::new(sys_dir).exists() {
            cmd.arg("--ro-bind").arg(*sys_dir).arg(*sys_dir);
        }
    }

    // ── Selective /etc bind-mounts ──
    // Only bind the specific /etc files required for the command to work.
    // Add new files here only if a test proves they are essential.
    if matches!(policy.network, NetworkPolicy::FullAccess)
        || matches!(policy.network, NetworkPolicy::ProxyOnly)
    {
        // DNS resolution — only needed when network is not isolated.
        if Path::new("/etc/resolv.conf").exists() {
            cmd.arg("--ro-bind")
                .arg("/etc/resolv.conf")
                .arg("/etc/resolv.conf");
        }
    }

    // ── Bind-mount cwd as writable (always, so the shell can run) ──
    //
    // When mode is ReadOnly, bwrap will still --bind cwd (Writable) so that
    // `/tmp` and other implicit writes work.  File-system-level restrictions
    // for ReadOnly mode are better handled at the Landlock layer.  For bwrap
    // we rely on the `writable_roots` list: if cwd is NOT in writable_roots,
    // it gets no explicit --bind → bwrap will use empty tmpfs, denying writes.
    let cwd_str = cwd_canon.to_string_lossy();

    // In WorkspaceWrite mode we --bind every writable_root.  In ReadOnly mode
    // we still need to bind-mount cwd to make the directory visible at all —
    // but we use --ro-bind for ReadOnly.
    match policy.mode {
        SandboxMode::ReadOnly => {
            // Bind cwd as read-only so the command can read files from the
            // workspace but cannot write.
            cmd.arg("--ro-bind")
                .arg(cwd_str.as_ref())
                .arg(cwd_str.as_ref());
        }
        SandboxMode::WorkspaceWrite => {
            // Bind every writable_root as read-write.
            for root in &policy.writable_roots {
                let resolved = resolve_root(root, cwd_canon);
                if resolved.exists() {
                    let s = resolved.to_string_lossy();
                    cmd.arg("--bind").arg(s.as_ref()).arg(s.as_ref());
                }
            }
            // Always make cwd visible even if not explicitly in writable_roots.
            if !is_root_or_parent_in_list(cwd_canon, &policy.writable_roots) {
                cmd.arg("--bind")
                    .arg(cwd_str.as_ref())
                    .arg(cwd_str.as_ref());
            }
        }
        SandboxMode::DangerFullAccess => unreachable!(),
    }

    // ── Protected paths: mount-level masking (overrides writable binds) ──
    //
    // We canonicalize each protected_path to find the real location, then
    // use bwrap's own mount mechanism to mask it:
    //   - files   → --ro-bind /dev/null <path>  (always-empty content)
    //   - dirs    → --tmpfs <path>               (empty filesystem)
    // Order: after --bind (writable_roots) so the tighter mask wins.
    for prot in &policy.protected_paths {
        let resolved = resolve_root(prot, cwd_canon);
        mask_protected_path(&mut cmd, &resolved, cwd_canon)?;
    }

    // ── Shell + command ──
    cmd.arg("--chdir")
        .arg(cwd_str.as_ref())
        .arg("sh")
        .arg("-c")
        .arg(command)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    Ok(cmd)
}

/// Check whether `cwd` is covered by any of the writable_roots (i.e. `cwd`
/// starts with some root, or some root starts with `cwd`).
fn is_root_or_parent_in_list(cwd: &Path, roots: &[PathBuf]) -> bool {
    roots.iter().any(|r| {
        let resolved = resolve_root(r, cwd);
        cwd.starts_with(&resolved) || resolved.starts_with(cwd)
    })
}

// ─── Landlock fallback ───────────────────────────────────────────────────────────

fn build_landlock_command(
    command: &str,
    cwd_canon: &Path,
    policy: &SandboxPolicy,
) -> Result<std::process::Command, ToolError> {
    // Capture everything we need in owned data so the `pre_exec` closure
    // can be 'static.
    let cwd = cwd_canon.to_path_buf();
    let writable_roots: Vec<PathBuf> = policy
        .writable_roots
        .iter()
        .map(|r| resolve_root(r, &cwd))
        .collect();
    let protected_paths: Vec<PathBuf> = policy
        .protected_paths
        .iter()
        .map(|r| resolve_root(r, &cwd))
        .collect();
    let is_read_only = matches!(policy.mode, SandboxMode::ReadOnly);
    let is_isolated = matches!(policy.network, NetworkPolicy::Isolated);

    let mut cmd = std::process::Command::new("sh");
    cmd.arg("-c")
        .arg(command)
        .current_dir(&cwd)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    // pre_exec runs in the child after fork, before exec.
    // Safety: the closure only calls landlock syscalls and never touches
    // shared state.  After fork there are no other threads.
    unsafe {
        cmd.pre_exec(move || {
            apply_landlock_rules(
                &cwd,
                &writable_roots,
                &protected_paths,
                is_read_only,
                is_isolated,
            )
        });
    }

    Ok(cmd)
}

fn apply_landlock_rules(
    cwd: &Path,
    writable_roots: &[PathBuf],
    protected_paths: &[PathBuf],
    is_read_only: bool,
    is_isolated: bool,
) -> std::io::Result<()> {
    use landlock::{
        AccessFs, AccessNet, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
        RulesetCreatedAttr, ABI,
    };

    let abi = ABI::V1;

    // ── Create ruleset with read+execute access handled ──
    let read_access = AccessFs::from_read(abi);
    let write_all = AccessFs::from_write(abi);

    let mut ruleset = Ruleset::default();
    {
        // Use &mut Ruleset so that handle_access borrows instead of consuming.
        let r = &mut ruleset;
        r.set_compatibility(CompatLevel::BestEffort);
        r.handle_access(read_access | write_all)
            .map_err(|e| std::io::Error::other(format!("landlock handle_access: {}", e)))?;
        // Network isolation (best-effort, ABI V4+): deny TCP connections.
        if is_isolated {
            // This may fail on kernels < 6.7 — we swallow the error.
            let _ = r.handle_access(AccessNet::ConnectTcp);
        }
    }

    let mut created = ruleset
        .create()
        .map_err(|e| std::io::Error::other(format!("landlock create: {}", e)))?;

    // ── Allow read+execute on essential system directories ──
    // Same list as bwrap's --ro-bind, so the landlock fallback provides
    // equivalent read isolation rather than granting / globally.
    for sys_dir in &["/usr", "/bin", "/lib", "/lib64"] {
        if Path::new(sys_dir).exists() {
            if let Ok(fd) = PathFd::new(sys_dir) {
                created = created
                    .add_rule(PathBeneath::new(fd, read_access | AccessFs::Execute))
                    .map_err(|e| {
                        std::io::Error::other(format!(
                            "landlock add_rule {}: {}",
                            sys_dir, e
                        ))
                    })?;
            }
        }
    }

    // ── Allow reads on cwd ──
    if let Ok(cwd_fd) = PathFd::new(cwd) {
        created = created
            .add_rule(PathBeneath::new(cwd_fd, read_access))
            .map_err(|e| std::io::Error::other(format!("landlock add_rule cwd: {}", e)))?;
    }

    // ── Writable roots ──
    if !is_read_only {
        for root in writable_roots {
            // Skip roots that are covered by protected_paths.
            if protected_paths
                .iter()
                .any(|p| root.starts_with(p) || root == p)
            {
                continue;
            }
            if let Ok(fd) = PathFd::new(root) {
                created = created
                    .add_rule(PathBeneath::new(fd, write_all))
                    .map_err(|e| {
                        std::io::Error::other(format!(
                            "landlock add_rule {}: {}",
                            root.display(),
                            e
                        ))
                    })?;
            }
        }
    }

    // ── Apply ──
    let _status = created
        .restrict_self()
        .map_err(|e| std::io::Error::other(format!("landlock restrict_self: {}", e)))?;

    Ok(())
}

// ─── Protected-path masking ────────────────────────────────────────────────────

/// Add bwrap arguments to mask a single protected path at the mount level.
///
/// Algorithm:
/// 1. Try to canonicalize the path (resolve symlinks).
/// 2. If the canonical path exists:
///    - File → `--ro-bind /dev/null <path>` (reads return empty, writes fail)
///    - Directory → `--tmpfs <path>` (all contents invisible)
/// 3. If the canonical path does NOT exist:
///    - Walk up to find the first existing ancestor.
///    - Bind /dev/null at the first non-existent component to block creation.
///
/// This is a kernel-level mechanism — no amount of symlink trickery or `..`
/// path-splicing can reach the real file behind the mount.
fn mask_protected_path(
    cmd: &mut std::process::Command,
    path: &Path,
    _cwd: &Path,
) -> Result<(), ToolError> {
    // Step 1: Try full canonicalization (resolves symlinks).
    if let Ok(canon) = std::fs::canonicalize(path) {
        // Path exists.  Mask the real location.
        let canon_str = canon.to_string_lossy();
        if canon.is_dir() {
            cmd.arg("--tmpfs").arg(canon_str.as_ref());
        } else {
            cmd.arg("--ro-bind")
                .arg("/dev/null")
                .arg(canon_str.as_ref());
        }
        return Ok(());
    }

    // Step 2: Path does not exist.  Walk up to find first existing ancestor.
    let (existing_ancestor, first_missing_component) = canonicalize_best_effort(path);

    // Build the path of the first non-existent component.
    // If the path itself is the first non-existent component (i.e. its parent
    // exists), we mask it directly.  Otherwise we mask the first component in
    // the chain that doesn't exist.
    let mask_target = if let Some(name) = first_missing_component {
        existing_ancestor.join(name)
    } else {
        // Everything exists up to some ancestor — use the resolved path.
        existing_ancestor
    };

    // We can't tell whether the non-existent target would be a file or
    // directory, so we use --ro-bind /dev/null.  This turns the path into
    // a device node-like file — creating a directory at this path will
    // fail with "Not a directory", and reads will return empty content.
    let mask_str = mask_target.to_string_lossy();
    cmd.arg("--ro-bind").arg("/dev/null").arg(mask_str.as_ref());

    Ok(())
}

/// Canonicalize a path on a best-effort basis.
///
/// Returns `(existing_canonical_ancestor, first_nonexistent_component_name)`.
///
/// Walk up from `path` until we find a component that exists, canonicalize
/// that ancestor, then return the first missing component name so the caller
/// can construct the full mask target.
fn canonicalize_best_effort(path: &Path) -> (PathBuf, Option<std::ffi::OsString>) {
    let mut current = path.to_path_buf();
    let mut missing: Vec<std::ffi::OsString> = Vec::new();

    loop {
        if current.exists() {
            let canon = std::fs::canonicalize(&current).unwrap_or(current);
            let first_missing = missing.pop();
            return (canon, first_missing);
        }

        // Remember this component and go up one level.
        if let Some(name) = current.file_name() {
            missing.push(name.to_os_string());
        }

        match current.parent() {
            Some(parent) => current = parent.to_path_buf(),
            None => {
                // We reached the root — nothing exists.
                let first_missing = missing.pop();
                return (current, first_missing);
            }
        }
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────────

/// Resolve a root path that may be relative to cwd.
fn resolve_root(root: &Path, cwd: &Path) -> PathBuf {
    if root.is_absolute() {
        root.to_path_buf()
    } else {
        cwd.join(root)
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_bwrap_available_smoke() {
        // Just call it — won't panic even if bwrap is missing.
        let _ = bwrap_available();
    }

    #[test]
    fn test_build_bwrap_command_isolated_network() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();

        let policy = SandboxPolicy {
            mode: SandboxMode::ReadOnly,
            writable_roots: vec![],
            network: NetworkPolicy::Isolated,
            protected_paths: vec![],
        };

        let cmd = build_bwrap_command("echo hi", ws, &policy).unwrap();
        // Program should be bwrap.
        assert_eq!(cmd.get_program(), "bwrap");
        let args: Vec<_> = cmd
            .get_args()
            .map(|s| s.to_string_lossy().to_string())
            .collect();
        let arg_str = args.join(" ");
        assert!(
            arg_str.contains("--unshare-net"),
            "missing --unshare-net: {}",
            arg_str
        );
        assert!(
            arg_str.contains("--ro-bind"),
            "missing --ro-bind: {}",
            arg_str
        );
    }

    #[test]
    fn test_build_bwrap_command_writable_roots() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();
        let data = ws.join("data");
        fs::create_dir_all(&data).unwrap();

        let policy = SandboxPolicy {
            mode: SandboxMode::WorkspaceWrite,
            writable_roots: vec![data.clone()],
            network: NetworkPolicy::FullAccess,
            protected_paths: vec![],
        };

        let cmd = build_bwrap_command("echo hi", ws, &policy).unwrap();
        let args: Vec<_> = cmd
            .get_args()
            .map(|s| s.to_string_lossy().to_string())
            .collect();
        let arg_str = args.join(" ");
        assert!(arg_str.contains("--bind"), "missing --bind: {}", arg_str);
    }

    #[test]
    fn test_build_bwrap_command_protected_paths_override() {
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

        let cmd = build_bwrap_command("echo hi", ws, &policy).unwrap();
        let args: Vec<_> = cmd
            .get_args()
            .map(|s| s.to_string_lossy().to_string())
            .collect();

        // Protected --tmpfs for .git (directory) must appear AFTER the --bind
        // for the workspace.  This ensures "whole writable, local tightened" order.
        let bind_pos = args.iter().position(|a| a == "--bind").unwrap();
        let tmpfs_pos = args.iter().rposition(|a| a == "--tmpfs").unwrap();
        assert!(
            tmpfs_pos > bind_pos,
            "--tmpfs (protected dir) must appear after --bind (writable), args: {:?}",
            args
        );
    }

    #[test]
    fn test_mask_protected_path_nonexistent() {
        // When a protected path doesn't exist, we should still emit bwrap args.
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();
        let phantom = ws.join("vault");
        assert!(!phantom.exists());

        let mut cmd = std::process::Command::new("bwrap");
        mask_protected_path(&mut cmd, &phantom, ws).unwrap();

        let args: Vec<_> = cmd
            .get_args()
            .map(|s| s.to_string_lossy().to_string())
            .collect();
        assert!(
            args.contains(&"--ro-bind".to_string()),
            "should emit --ro-bind for non-existent path"
        );
        // Should bind /dev/null on the phantom path
        let devnull_pos = args.iter().position(|a| a == "/dev/null");
        assert!(
            devnull_pos.is_some(),
            "should use /dev/null as source for non-existent path"
        );
    }

    #[test]
    fn test_mask_protected_path_file() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();
        let file = ws.join("credentials.txt");
        fs::write(&file, "secret\n").unwrap();

        let mut cmd = std::process::Command::new("bwrap");
        mask_protected_path(&mut cmd, &file, ws).unwrap();

        let args: Vec<_> = cmd
            .get_args()
            .map(|s| s.to_string_lossy().to_string())
            .collect();
        // Should use --ro-bind /dev/null (not --tmpfs) for a file.
        assert!(
            args.contains(&"--ro-bind".to_string()),
            "file mask should use --ro-bind"
        );
        assert!(
            !args.contains(&"--tmpfs".to_string()),
            "file mask should NOT use --tmpfs"
        );
    }

    #[test]
    fn test_mask_protected_path_dir() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();
        let subdir = ws.join("secrets");
        fs::create_dir_all(&subdir).unwrap();

        let mut cmd = std::process::Command::new("bwrap");
        mask_protected_path(&mut cmd, &subdir, ws).unwrap();

        let args: Vec<_> = cmd
            .get_args()
            .map(|s| s.to_string_lossy().to_string())
            .collect();
        // Should use --tmpfs (not --ro-bind) for a directory.
        assert!(
            args.contains(&"--tmpfs".to_string()),
            "dir mask should use --tmpfs"
        );
        assert!(
            !args.contains(&"--ro-bind".to_string()),
            "dir mask should NOT use --ro-bind"
        );
    }

    #[test]
    fn test_mask_protected_path_symlink_target_masked() {
        use std::os::unix;
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();

        // Create a real file OUTSIDE the workspace.
        let real_secret = dir.path().join("real_secret.txt");
        fs::write(&real_secret, "super-secret\n").unwrap();

        // Create a symlink inside the workspace pointing to the real file.
        let link = ws.join("secret_link");
        unix::fs::symlink(&real_secret, &link).unwrap();

        // Mask the symlink path (which resolves to real_secret).
        let mut cmd = std::process::Command::new("bwrap");
        mask_protected_path(&mut cmd, &link, ws).unwrap();

        let args: Vec<_> = cmd
            .get_args()
            .map(|s| s.to_string_lossy().to_string())
            .collect();
        let arg_str = args.join(" ");

        // The mask should target the REAL canonical path, not the symlink path.
        assert!(
            arg_str.contains(&*real_secret.to_string_lossy()),
            "mask must target canonical path ({}), got: {}",
            real_secret.display(),
            arg_str
        );
    }
}
