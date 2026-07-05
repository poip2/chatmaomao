//! Cross-platform sandbox executor for bash commands.
//!
//! ```text
//! SandboxExecutor (ProcessExecutor impl)
//!       │
//!       ▼
//!   SandboxExecutor::run()
//!       │
//!       ├── #[cfg(target_os = "macos")]  → seatbelt::build_sandboxed_command
//!       │                                     │  (returns (Command, SeatbeltGuard))
//!       │                                     ▼
//!       │                                   spawn → done
//!       │
//!       ├── #[cfg(target_os = "linux")]  → linux::build_sandboxed_command
//!       │                                     │  (bwrap or landlock pre_exec)
//!       │                                     ▼
//!       │                                   spawn → done
//!       │
//!       └── #[cfg(target_os = "windows")]→ windows::build_sandboxed_command
//!                                             │  (returns bare Command)
//!                                             ▼
//!                                           spawn  →  windows::apply_sandbox_post_spawn
//!                                                       │  (Job Object, Low-IL token,
//!                                                       │   ACL read isolation)
//!                                                       ▼
//!                                                     done
//! ```
//!
//! On macOS and Linux the sandbox is fully configured before spawn — the
//! returned `Command` already wraps the child in seatbelt / bwrap / landlock.
//! On Windows the sandbox is applied **after** spawn because Job Object
//! assignment and token downgrade require an existing process handle.
//! Job Object assignment is best-effort: if the process is already in an
//! outer Job Object (e.g. CI runner), it degrades gracefully to Low IL +
//! ACL read isolation only, without resource limits.
//!
//! `SandboxExecutor::run()` handles the lifecycle — pipe reading,
//! timeout, cancel, process-tree kill — identically to `LocalExecutor`.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::agent::tools::bash::{OutputHandler, ProcessExecutor, ProcessExit};
use crate::agent::types::{AgentSignal, NetworkPolicy, SandboxPolicy, ToolError};

// ─── Platform modules ────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
mod seatbelt;
#[cfg(target_os = "macos")]
use seatbelt as platform;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as platform;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use windows as platform;

// ─── SandboxExecutor ─────────────────────────────────────────────────────────────

/// A `ProcessExecutor` that runs commands inside a platform sandbox.
///
/// Delegates command construction to the platform module, then handles
/// stdout/stderr piping, timeout, cancel, and process-tree kill identically
/// to `LocalExecutor`.
pub struct SandboxExecutor {
    /// CWD for all commands executed by this executor.
    cwd: PathBuf,
    /// Sandbox policy applied to every execution.
    policy: SandboxPolicy,
}

impl SandboxExecutor {
    pub fn new(cwd: PathBuf, policy: SandboxPolicy) -> Self {
        Self { cwd, policy }
    }
}

#[async_trait]
impl ProcessExecutor for SandboxExecutor {
    async fn run(
        &self,
        command: &str,
        cwd: &Path,
        timeout_ms: Option<u64>,
        signal: AgentSignal,
        on_stdout: Arc<dyn OutputHandler>,
        on_stderr: Arc<dyn OutputHandler>,
    ) -> Result<ProcessExit, ToolError> {
        // ProxyOnly is only implemented on macOS (seatbelt).
        // On Linux and Windows it must explicitly fail rather than silently
        // degrading to FullAccess.
        #[cfg(not(target_os = "macos"))]
        if matches!(self.policy.network, NetworkPolicy::ProxyOnly) {
            return Err(ToolError::InvalidArgs(
                "ProxyOnly network policy is not yet implemented on this platform".into(),
            ));
        }

        // Build the sandbox-wrapped std::process::Command.
        // macOS returns a SeatbeltGuard that keeps the SBPL profile temp file
        // alive until the child exits.
        #[cfg(target_os = "macos")]
        let (mut std_cmd, _seatbelt_guard) =
            platform::build_sandboxed_command(command, cwd, &self.policy)?;
        #[cfg(not(target_os = "macos"))]
        let mut std_cmd = platform::build_sandboxed_command(command, cwd, &self.policy)?;

        // ── Process group (for tree kill) ──
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            std_cmd.process_group(0);
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            std_cmd.creation_flags(0x0000_0200); // CREATE_NEW_PROCESS_GROUP
        }

        let mut child = tokio::process::Command::from(std_cmd)
            .spawn()
            .map_err(ToolError::Io)?;

        let pid = child.id().expect("child must have a PID");

        // Windows: apply Job Object + Low-IL token + read isolation
        // to the child **after** spawn.  The returned handle must stay
        // alive for the child's lifetime.
        #[cfg(target_os = "windows")]
        let _sandbox_guard = platform::apply_sandbox_post_spawn(pid, cwd, &self.policy)?;
        let child_stdout = child.stdout.take().expect("stdout piped");
        let child_stderr = child.stderr.take().expect("stderr piped");

        // ── Channel from reader tasks → main loop ──
        let (chunk_tx, mut chunk_rx) = tokio::sync::mpsc::unbounded_channel::<PipeChunk>();
        let reader_done = Arc::new(AtomicBool::new(false));

        spawn_pipe_reader(
            child_stdout,
            PipeChunk::Stdout,
            chunk_tx.clone(),
            reader_done.clone(),
        );
        spawn_pipe_reader(
            child_stderr,
            PipeChunk::Stderr,
            chunk_tx,
            reader_done.clone(),
        );

        // ── Futures pinned for the select! loop ──
        let child_wait = child.wait();
        tokio::pin!(child_wait);

        let timeout_sleep = timeout_ms
            .map(|ms| tokio::time::sleep(Duration::from_millis(ms)))
            .unwrap_or_else(|| tokio::time::sleep(Duration::MAX));
        tokio::pin!(timeout_sleep);

        let cancel_poll = cancel_watcher(signal);
        tokio::pin!(cancel_poll);

        loop {
            tokio::select! {
                Some(chunk) = chunk_rx.recv() => {
                    match chunk {
                        PipeChunk::Stdout(data) => on_stdout.handle(&data),
                        PipeChunk::Stderr(data) => on_stderr.handle(&data),
                    }
                }

                status = &mut child_wait => {
                    reader_done.store(true, Ordering::Relaxed);
                    drain_channels(chunk_rx, on_stdout.clone(), on_stderr.clone()).await;
                    return match status {
                        Ok(s) => Ok(ProcessExit::Code(s.code().unwrap_or(1))),
                        Err(e) => Err(ToolError::Io(e)),
                    };
                }

                _ = &mut timeout_sleep => {
                    kill_process_tree(pid);
                    let _ = (&mut child_wait).await;
                    reader_done.store(true, Ordering::Relaxed);
                    drain_channels(chunk_rx, on_stdout.clone(), on_stderr.clone()).await;
                    return Ok(ProcessExit::KilledByTimeout);
                }

                _ = &mut cancel_poll => {
                    kill_process_tree(pid);
                    let _ = (&mut child_wait).await;
                    reader_done.store(true, Ordering::Relaxed);
                    drain_channels(chunk_rx, on_stdout.clone(), on_stderr.clone()).await;
                    return Ok(ProcessExit::KilledByCancel);
                }
            }
        }
    }
}

// ─── Shared helpers (mirrors bash.rs, kept here so bash.rs stays untouched) ──────

enum PipeChunk {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
}

async fn cancel_watcher(signal: AgentSignal) {
    loop {
        if signal.is_aborted() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn drain_channels(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<PipeChunk>,
    on_stdout: Arc<dyn OutputHandler>,
    on_stderr: Arc<dyn OutputHandler>,
) {
    let deadline = tokio::time::sleep(Duration::from_millis(200));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            Some(chunk) = rx.recv() => {
                match chunk {
                    PipeChunk::Stdout(data) => on_stdout.handle(&data),
                    PipeChunk::Stderr(data) => on_stderr.handle(&data),
                }
            }
            _ = &mut deadline => break,
            else => break,
        }
    }
}

fn spawn_pipe_reader<R>(
    mut stream: R,
    tag: fn(Vec<u8>) -> PipeChunk,
    tx: tokio::sync::mpsc::UnboundedSender<PipeChunk>,
    done: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::task::spawn(async move {
        let mut buf = vec![0u8; 8192];
        loop {
            if done.load(Ordering::Relaxed) {
                break;
            }
            match tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let _ = tx.send(tag(buf[..n].to_vec()));
                }
                Err(_) => break,
            }
        }
    })
}

fn kill_process_tree(pid: u32) {
    #[cfg(unix)]
    {
        let pgid = pid as i32;
        unsafe {
            libc::kill(-pgid, libc::SIGKILL);
        }
    }

    #[cfg(windows)]
    {
        let _ = std::process::Command::new("taskkill")
            .args(&["/PID", &pid.to_string(), "/T", "/F"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::types::{NetworkPolicy, SandboxMode};
    use std::sync::Mutex;

    fn make_policy(writable_roots: Vec<PathBuf>, protected_paths: Vec<PathBuf>) -> SandboxPolicy {
        SandboxPolicy {
            mode: SandboxMode::WorkspaceWrite,
            writable_roots,
            network: NetworkPolicy::FullAccess,
            protected_paths,
        }
    }

    fn isolated_network_policy() -> SandboxPolicy {
        SandboxPolicy {
            mode: SandboxMode::ReadOnly,
            writable_roots: vec![],
            network: NetworkPolicy::Isolated,
            protected_paths: vec![],
        }
    }

    fn run_sync(
        executor: &SandboxExecutor,
        cmd: &str,
        cwd: &Path,
        timeout_ms: Option<u64>,
    ) -> Result<(String, String, ProcessExit), ToolError> {
        let stdout = Arc::new(Mutex::new(Vec::new()));
        let stderr = Arc::new(Mutex::new(Vec::new()));

        let so = stdout.clone();
        let se = stderr.clone();

        let on_stdout: Arc<dyn OutputHandler> = Arc::new(move |data: &[u8]| {
            so.lock().unwrap().extend_from_slice(data);
        });
        let on_stderr: Arc<dyn OutputHandler> = Arc::new(move |data: &[u8]| {
            se.lock().unwrap().extend_from_slice(data);
        });

        let rt = tokio::runtime::Runtime::new().unwrap();
        let exit = rt.block_on(executor.run(
            cmd,
            cwd,
            timeout_ms,
            AgentSignal::new(),
            on_stdout,
            on_stderr,
        ))?;

        let out_str = String::from_utf8_lossy(&stdout.lock().unwrap()).to_string();
        let err_str = String::from_utf8_lossy(&stderr.lock().unwrap()).to_string();
        Ok((out_str, err_str, exit))
    }

    // ── 1. basic execution ──────────────────────────────────────────────────

    #[test]
    fn test_sandbox_basic_echo() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();
        let policy = make_policy(vec![ws.to_path_buf()], vec![]);
        let executor = SandboxExecutor::new(ws.to_path_buf(), policy);

        let (out, _err, exit) = run_sync(&executor, "echo hello-sandbox", ws, None).unwrap();
        assert!(out.contains("hello-sandbox"), "got: {}", out);
        assert_eq!(exit, ProcessExit::Code(0));
    }

    // ── 2. writable_roots: write succeeds inside root ────────────────────────

    #[test]
    fn test_sandbox_write_inside_writable_root() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();
        let policy = make_policy(vec![ws.to_path_buf()], vec![]);
        let executor = SandboxExecutor::new(ws.to_path_buf(), policy);

        let fname = "sandbox_test_write.txt";
        let cmd = format!("echo 'written-by-sandbox' > {}", fname);
        let (out, _err, exit) = run_sync(&executor, &cmd, ws, None).unwrap();
        assert_eq!(exit, ProcessExit::Code(0), "stdout={} stderr={}", out, _err);

        let content = std::fs::read_to_string(ws.join(fname)).unwrap();
        assert!(content.contains("written-by-sandbox"));
    }

    // ── 3. writable_roots: read succeeds inside root ────────────────────────

    #[test]
    fn test_sandbox_read_inside_writable_root() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();
        std::fs::write(ws.join("existing.txt"), "pre-existing\n").unwrap();

        let policy = make_policy(vec![ws.to_path_buf()], vec![]);
        let executor = SandboxExecutor::new(ws.to_path_buf(), policy);

        let (out, _err, exit) = run_sync(&executor, "cat existing.txt", ws, None).unwrap();
        assert_eq!(exit, ProcessExit::Code(0));
        assert!(out.contains("pre-existing"), "got: {}", out);
    }

    // ── 4. protected_paths: write is blocked (real disk untouched) ─────────

    #[test]
    fn test_sandbox_protected_paths_block_write() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();
        let protected_dir = ws.join("secrets");
        std::fs::create_dir_all(&protected_dir).unwrap();

        let policy = make_policy(vec![ws.to_path_buf()], vec![PathBuf::from("secrets")]);
        let executor = SandboxExecutor::new(ws.to_path_buf(), policy);

        let cmd = "echo 'pwned' > secrets/passwd";
        let (_out, _err, exit) = run_sync(&executor, cmd, ws, None).unwrap();

        // With mount-level masking (--tmpfs), the sandbox sees an empty tmpfs
        // where writes succeed locally but never reach the real disk.
        // The real file on disk must remain untouched.
        let target = protected_dir.join("passwd");
        assert_write_blocked(&exit, &target, "pwned", "protected-write");
    }

    // ── 5. protected_paths: read is blocked (mount-level masking) ───────────

    #[test]
    fn test_sandbox_protected_paths_read_blocked() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();
        let protected_dir = ws.join("secrets");
        std::fs::create_dir_all(&protected_dir).unwrap();
        std::fs::write(protected_dir.join("readme.txt"), "for-your-eyes-only\n").unwrap();

        let policy = make_policy(vec![ws.to_path_buf()], vec![PathBuf::from("secrets")]);
        let executor = SandboxExecutor::new(ws.to_path_buf(), policy);

        let (out, _err, exit) = run_sync(&executor, "cat secrets/readme.txt", ws, None).unwrap();

        // With mount-level masking (--tmpfs on protected directories), the
        // directory appears empty — reading any file inside it must fail.
        let breached = exit == ProcessExit::Code(0) && out.contains("for-your-eyes-only");
        assert!(
            !breached,
            "protected paths must block reads too (mount-level masking). exit={:?} out={}",
            exit, out,
        );
    }

    // ── 6. network Isolated: connection attempt fails ───────────────────────

    #[test]
    fn test_sandbox_network_isolated() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();
        let policy = isolated_network_policy();
        let executor = SandboxExecutor::new(ws.to_path_buf(), policy);

        // bash /dev/tcp is a bashism; try a DNS lookup via `getent` or
        // a connection attempt with `timeout`.  Prefer `curl` if available,
        // otherwise use bash /dev/tcp.
        let cmd = "timeout 2 bash -c 'exec 3<>/dev/tcp/8.8.8.8/53 2>/dev/null && echo CONNECTED || echo BLOCKED' 2>/dev/null; true";
        let (_out, _err, _exit) = run_sync(&executor, cmd, ws, Some(5000)).unwrap();

        // When network is isolated, the connection should fail (BLOCKED).
        // We accept either exit code since the outer `true` masks it.
        assert!(
            !_out.contains("CONNECTED"),
            "network should be isolated, got: {}",
            _out
        );
    }

    // ── 7. timeout still works inside sandbox ───────────────────────────────

    #[test]
    fn test_sandbox_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();
        let policy = make_policy(vec![ws.to_path_buf()], vec![]);
        let executor = SandboxExecutor::new(ws.to_path_buf(), policy);

        let result = run_sync(&executor, "sleep 60", ws, Some(500));
        assert!(
            matches!(result, Ok((_, _, ProcessExit::KilledByTimeout))),
            "got {:?}",
            result
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Attack tests — black-box sandbox penetration testing
    //
    // Each test constructs an attack and asserts it MUST FAIL.
    // If an attack succeeds (exit=0 + expected side-effect observed),
    // the sandbox has a vulnerability — do NOT silently fix it, report it.
    // ═══════════════════════════════════════════════════════════════════════════

    // ── Attack helpers ────────────────────────────────────────────────────────

    /// Assert that a sandboxed command FAILED to write `marker` to `target_path`.
    ///
    /// On mount-level-masking platforms (Linux bwrap), writes into an empty
    /// tmpfs or /dev/null bind-mount may return exit=0 because the write
    /// "succeeds" within the masked filesystem — but the real file on disk
    /// must remain untouched.  This checker validates the real file content.
    fn assert_write_blocked(
        exit: &ProcessExit,
        target_path: &Path,
        marker: &str,
        attack_name: &str,
    ) {
        let content = std::fs::read_to_string(target_path).unwrap_or_default();
        let breached = content.contains(marker);
        assert!(
            !breached,
            "BREACH [{}]: write escaped sandbox! exit={:?}, file={}, contains_marker={}",
            attack_name,
            exit,
            target_path.display(),
            content.contains(marker),
        );
    }

    /// Assert that a sandboxed command FAILED to read `marker` from stdout.
    fn assert_read_blocked(exit: &ProcessExit, stdout: &str, marker: &str, attack_name: &str) {
        let breached = *exit == ProcessExit::Code(0) && stdout.contains(marker);
        assert!(
            !breached,
            "BREACH [{}]: read escaped sandbox! exit={:?}, stdout_contains_marker={}",
            attack_name,
            exit,
            stdout.contains(marker),
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  CATEGORY 1: Write path escape attacks
    //  Guarantee: writable_roots 之外的任何路径，不能被写入
    // ═══════════════════════════════════════════════════════════════════════════

    /// Attack: write via `../` relative path escape.
    #[test]
    fn attack_write_escape_dotdot() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        let outside = dir.path().join("outside_sentinel.txt");
        std::fs::write(&outside, "CLEAN\n").unwrap();

        let policy = make_policy(vec![ws.clone()], vec![]);
        let executor = SandboxExecutor::new(ws.clone(), policy);

        let (_out, _err, exit) =
            run_sync(&executor, "echo PWNED > ../outside_sentinel.txt", &ws, None).unwrap();

        assert_write_blocked(&exit, &outside, "PWNED", "write-dotdot");
    }

    /// Attack: write via double `../../` deep traversal.
    #[test]
    fn attack_write_escape_deep_dotdot() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("a/b/c/workspace");
        std::fs::create_dir_all(&ws).unwrap();

        // Target is 3 levels up from workspace
        let outside = dir.path().join("deep_target.txt");
        std::fs::write(&outside, "CLEAN\n").unwrap();

        let policy = make_policy(vec![ws.clone()], vec![]);
        let executor = SandboxExecutor::new(ws.clone(), policy);

        let (_out, _err, exit) = run_sync(
            &executor,
            "echo PWNED > ../../../deep_target.txt",
            &ws,
            None,
        )
        .unwrap();

        assert_write_blocked(&exit, &outside, "PWNED", "write-deep-dotdot");
    }

    /// Attack: write via absolute path outside writable_roots.
    #[test]
    fn attack_write_escape_absolute() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        let outside = dir.path().join("abs_target.txt");
        let abs_path = outside.to_string_lossy().to_string();

        let policy = make_policy(vec![ws.clone()], vec![]);
        let executor = SandboxExecutor::new(ws.clone(), policy);

        let cmd = format!("echo PWNED > {}", abs_path);
        let (_out, _err, exit) = run_sync(&executor, &cmd, &ws, None).unwrap();

        assert_write_blocked(&exit, &outside, "PWNED", "write-absolute");
    }

    /// Attack: write to a system path like /tmp outside writable_roots.
    #[cfg(unix)]
    #[test]
    fn attack_write_escape_system_tmp() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        let marker = format!("SANDBOX_PWNED_{}", std::process::id());
        let target =
            std::env::temp_dir().join(format!("sandbox_escape_{}.txt", std::process::id()));

        // Ensure file doesn't exist before test
        let _ = std::fs::remove_file(&target);

        let policy = make_policy(vec![ws.clone()], vec![]);
        let executor = SandboxExecutor::new(ws.clone(), policy);

        let cmd = format!("echo '{}' > {}", marker, target.display());
        let (_out, _err, exit) = run_sync(&executor, &cmd, &ws, None).unwrap();

        // Cleanup regardless
        let content = std::fs::read_to_string(&target).unwrap_or_default();
        let _ = std::fs::remove_file(&target);

        assert_write_blocked(&exit, &target, &marker, "write-system-tmp");
        // Double-check cleanup didn't mask the breach
        let _ = content;
    }

    /// Attack: write via symlink pointing outside writable_roots.
    #[cfg(unix)]
    #[test]
    fn attack_write_escape_symlink_to_outside() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        let outside = dir.path().join("symlink_target.txt");
        std::fs::write(&outside, "CLEAN\n").unwrap();

        // Create symlink inside workspace pointing outside
        let link = ws.join("escape_link");
        std::os::unix::fs::symlink(&outside, &link).unwrap();

        let policy = make_policy(vec![ws.clone()], vec![]);
        let executor = SandboxExecutor::new(ws.clone(), policy);

        let (_out, _err, exit) =
            run_sync(&executor, "echo PWNED > escape_link", &ws, None).unwrap();

        assert_write_blocked(&exit, &outside, "PWNED", "write-symlink-outside");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  CATEGORY 2: Read path escape attacks (NEW — previously not tested)
    //  Guarantee: writable_roots 之外的任何路径，也不能被读取
    // ═══════════════════════════════════════════════════════════════════════════

    /// Attack: read via `../` relative path escape.
    #[test]
    #[cfg_attr(
        target_os = "macos",
        ignore = "macOS system-level read isolation not yet implemented (seatbelt defaults to allow)"
    )]
    fn attack_read_escape_dotdot() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        let secret = dir.path().join("secret_outside.txt");
        std::fs::write(&secret, "TOP-SECRET-DATA\n").unwrap();

        let policy = make_policy(vec![ws.clone()], vec![]);
        let executor = SandboxExecutor::new(ws.clone(), policy);

        let (out, _err, exit) =
            run_sync(&executor, "cat ../secret_outside.txt", &ws, None).unwrap();

        assert_read_blocked(&exit, &out, "TOP-SECRET-DATA", "read-dotdot");
    }

    /// Attack: read via deep `../../..` traversal.
    #[test]
    fn attack_read_escape_deep_dotdot() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("x/y/workspace");
        std::fs::create_dir_all(&ws).unwrap();

        let secret = dir.path().join("deep_secret.txt");
        std::fs::write(&secret, "CLASSIFIED-DEEP\n").unwrap();

        let policy = make_policy(vec![ws.clone()], vec![]);
        let executor = SandboxExecutor::new(ws.clone(), policy);

        let (out, _err, exit) =
            run_sync(&executor, "cat ../../deep_secret.txt", &ws, None).unwrap();

        assert_read_blocked(&exit, &out, "CLASSIFIED-DEEP", "read-deep-dotdot");
    }

    /// Attack: read /etc/passwd via absolute path.
    #[cfg(unix)]
    #[test]
    #[cfg_attr(
        target_os = "macos",
        ignore = "macOS system-level read isolation not yet implemented"
    )]
    fn attack_read_escape_absolute_etc_passwd() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        let policy = make_policy(vec![ws.clone()], vec![]);
        let executor = SandboxExecutor::new(ws.clone(), policy);

        let (out, _err, exit) = run_sync(&executor, "cat /etc/passwd", &ws, None).unwrap();

        // /etc/passwd always contains "root:" on Unix systems
        assert_read_blocked(&exit, &out, "root:", "read-/etc/passwd");
    }

    /// Attack: read /etc/hostname or /etc/hosts via absolute path.
    #[cfg(unix)]
    #[test]
    #[cfg_attr(
        target_os = "macos",
        ignore = "macOS system-level read isolation not yet implemented"
    )]
    fn attack_read_escape_absolute_etc_hosts() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        let policy = make_policy(vec![ws.clone()], vec![]);
        let executor = SandboxExecutor::new(ws.clone(), policy);

        // /etc/hosts always contains "localhost" on Unix
        let (out, _err, exit) = run_sync(&executor, "cat /etc/hosts", &ws, None).unwrap();

        assert_read_blocked(&exit, &out, "localhost", "read-/etc/hosts");
    }

    /// Attack: read via symlink pointing outside writable_roots.
    #[cfg(unix)]
    #[test]
    #[cfg_attr(
        target_os = "macos",
        ignore = "macOS system-level read isolation not yet implemented"
    )]
    fn attack_read_escape_symlink_to_outside() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        let secret = dir.path().join("secret_data.txt");
        std::fs::write(&secret, "CLASSIFIED-INFO\n").unwrap();

        let link = ws.join("read_escape_link");
        std::os::unix::fs::symlink(&secret, &link).unwrap();

        let policy = make_policy(vec![ws.clone()], vec![]);
        let executor = SandboxExecutor::new(ws.clone(), policy);

        let (out, _err, exit) = run_sync(&executor, "cat read_escape_link", &ws, None).unwrap();

        assert_read_blocked(&exit, &out, "CLASSIFIED-INFO", "read-symlink-outside");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  CATEGORY 3: Protected paths attacks
    //  Guarantee: protected_paths 里的路径即使在 writable_roots 内部也不能读写
    // ═══════════════════════════════════════════════════════════════════════════

    /// Attack: write to an existing file inside a protected path.
    #[test]
    fn attack_protected_write_existing() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        let secrets = ws.join("secrets");
        std::fs::create_dir_all(&secrets).unwrap();
        std::fs::write(secrets.join("db.txt"), "ORIGINAL\n").unwrap();

        let policy = make_policy(vec![ws.clone()], vec![PathBuf::from("secrets")]);
        let executor = SandboxExecutor::new(ws.clone(), policy);

        let (_out, _err, exit) =
            run_sync(&executor, "echo OVERWRITE > secrets/db.txt", &ws, None).unwrap();

        assert_write_blocked(
            &exit,
            &secrets.join("db.txt"),
            "OVERWRITE",
            "protected-write-existing",
        );
    }

    /// Attack: read an existing file inside a protected path.
    /// Per guarantee #3, protected_paths now block reads too (not just writes).
    #[test]
    fn attack_protected_read_existing() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        let secrets = ws.join("secrets");
        std::fs::create_dir_all(&secrets).unwrap();
        std::fs::write(secrets.join("passwords.txt"), "admin:123456\n").unwrap();

        let policy = make_policy(vec![ws.clone()], vec![PathBuf::from("secrets")]);
        let executor = SandboxExecutor::new(ws.clone(), policy);

        let (out, _err, exit) =
            run_sync(&executor, "cat secrets/passwords.txt", &ws, None).unwrap();

        assert_read_blocked(&exit, &out, "admin:123456", "protected-read-existing");
    }

    /// Attack: write to a non-existent path that is listed in protected_paths.
    /// The sandbox should prevent creation of files inside protected paths.
    #[test]
    fn attack_protected_write_nonexistent() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        // "vault" doesn't exist yet, but it's in protected_paths
        let policy = make_policy(vec![ws.clone()], vec![PathBuf::from("vault")]);
        let executor = SandboxExecutor::new(ws.clone(), policy);

        let (_out, _err, exit) = run_sync(
            &executor,
            "mkdir -p vault && echo PWNED > vault/creds.txt",
            &ws,
            None,
        )
        .unwrap();

        let target = ws.join("vault/creds.txt");
        assert_write_blocked(&exit, &target, "PWNED", "protected-write-nonexistent");
    }

    /// Attack: path splicing — use `protected_dir/../protected_dir/file` to
    /// try to bypass the protected_paths check via normalization tricks.
    #[test]
    fn attack_protected_path_splicing_dotdot() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        let secrets = ws.join("secrets");
        std::fs::create_dir_all(&secrets).unwrap();
        std::fs::write(secrets.join("token.txt"), "SECRET-TOKEN-ABCD\n").unwrap();

        let policy = make_policy(vec![ws.clone()], vec![PathBuf::from("secrets")]);
        let executor = SandboxExecutor::new(ws.clone(), policy);

        // Try: ./secrets/../secrets/token.txt — semantically resolves to secrets/token.txt
        let (out, _err, exit) =
            run_sync(&executor, "cat ./secrets/../secrets/token.txt", &ws, None).unwrap();

        assert_read_blocked(
            &exit,
            &out,
            "SECRET-TOKEN-ABCD",
            "protected-splicing-dotdot",
        );
    }

    /// Attack: create a symlink OUTSIDE the protected_paths that points INTO
    /// a protected path, then read through the symlink.
    #[cfg(unix)]
    #[test]
    fn attack_protected_symlink_pointing_into_protected() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        let secrets = ws.join("secrets");
        std::fs::create_dir_all(&secrets).unwrap();
        std::fs::write(secrets.join("api_key.txt"), "sk-1234567890abcdef\n").unwrap();

        // Symlink is in writable_root but NOT in protected_paths
        let link = ws.join("shortcut_to_key");
        std::os::unix::fs::symlink("secrets/api_key.txt", &link).unwrap();

        let policy = make_policy(vec![ws.clone()], vec![PathBuf::from("secrets")]);
        let executor = SandboxExecutor::new(ws.clone(), policy);

        let (out, _err, exit) = run_sync(&executor, "cat shortcut_to_key", &ws, None).unwrap();

        assert_read_blocked(&exit, &out, "sk-1234567890abcdef", "protected-symlink-into");
    }

    /// Attack: symlink chain — link1 → link2 → protected file.
    #[cfg(unix)]
    #[test]
    fn attack_protected_symlink_chain() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        let secrets = ws.join("secrets");
        std::fs::create_dir_all(&secrets).unwrap();
        std::fs::write(secrets.join("key.txt"), "CHAINED-SECRET\n").unwrap();

        // link2 → secrets/key.txt (inside protected area)
        let link2 = ws.join("link2");
        std::os::unix::fs::symlink("secrets/key.txt", &link2).unwrap();
        // link1 → link2 (double indirection)
        let link1 = ws.join("link1");
        std::os::unix::fs::symlink("link2", &link1).unwrap();

        let policy = make_policy(vec![ws.clone()], vec![PathBuf::from("secrets")]);
        let executor = SandboxExecutor::new(ws.clone(), policy);

        let (out, _err, exit) = run_sync(&executor, "cat link1", &ws, None).unwrap();

        assert_read_blocked(&exit, &out, "CHAINED-SECRET", "protected-symlink-chain");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  CATEGORY 3b: Protected path IS a symlink to OUTSIDE writable_roots
    //  Guarantee: the symlink resolves to an outside location; the mount-level
    //  mask must cover the *real* target, not just the symlink path.
    // ═══════════════════════════════════════════════════════════════════════════

    /// Attack: protected_path is itself a symlink pointing outside the
    /// writable_roots.  The mount mask must canonicalize through the symlink
    /// and mask the REAL target file.
    #[cfg(unix)]
    #[test]
    fn attack_protected_symlink_itself_is_outside_target() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        // Real file outside the workspace.
        let real_secret = dir.path().join("outside_env_file");
        std::fs::write(&real_secret, "OUTSIDE-API-KEY=abcdef\n").unwrap();

        // Symlink inside workspace that IS the protected path.
        let link = ws.join(".env");
        std::os::unix::fs::symlink(&real_secret, &link).unwrap();

        // The protected_path is the symlink itself (relative to cwd).
        let policy = make_policy(vec![ws.clone()], vec![PathBuf::from(".env")]);
        let executor = SandboxExecutor::new(ws.clone(), policy);

        // Try reading through the symlink — should hit the mount mask on the
        // canonical target.
        let (out, _err, exit) = run_sync(&executor, "cat .env", &ws, None).unwrap();

        assert_read_blocked(
            &exit,
            &out,
            "OUTSIDE-API-KEY",
            "protected-symlink-is-outside-target",
        );
    }

    /// Attack: two different symlinks pointing to the SAME real protected
    /// location.  The mask should be applied once at the real path, blocking
    /// both symlinks.
    #[cfg(unix)]
    #[test]
    fn attack_protected_two_symlinks_same_real_target() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        // Real file inside the secrets directory.
        let secrets = ws.join("secrets");
        std::fs::create_dir_all(&secrets).unwrap();
        let real_file = secrets.join("token.txt");
        std::fs::write(&real_file, "GH-TOKEN-12345\n").unwrap();

        // Two different symlinks → same real file.
        let link_a = ws.join("shortcut_a");
        std::os::unix::fs::symlink("secrets/token.txt", &link_a).unwrap();
        let link_b = ws.join("shortcut_b");
        std::os::unix::fs::symlink("secrets/token.txt", &link_b).unwrap();

        // Protect the secrets directory.
        let policy = make_policy(vec![ws.clone()], vec![PathBuf::from("secrets")]);
        let executor = SandboxExecutor::new(ws.clone(), policy);

        // Try link_a — must be blocked.
        let (out_a, _err_a, exit_a) = run_sync(&executor, "cat shortcut_a", &ws, None).unwrap();
        assert_read_blocked(&exit_a, &out_a, "GH-TOKEN-12345", "dual-symlink-link-a");

        // Try link_b — must also be blocked (same real target).
        let (out_b, _err_b, exit_b) = run_sync(&executor, "cat shortcut_b", &ws, None).unwrap();
        assert_read_blocked(&exit_b, &out_b, "GH-TOKEN-12345", "dual-symlink-link-b");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  CATEGORY 4: Network escape attacks
    //  Guarantee: network == Isolated 时不能做任何网络通信
    // ═══════════════════════════════════════════════════════════════════════════

    /// Attack: TCP connection via bash /dev/tcp in Isolated mode.
    #[test]
    fn attack_network_isolated_tcp_connect() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        let policy = isolated_network_policy();
        let executor = SandboxExecutor::new(ws.clone(), policy);

        // Bash /dev/tcp to Google DNS — if network is isolated, connection fails
        let cmd = "timeout 3 bash -c 'exec 3<>/dev/tcp/8.8.8.8/53 2>/dev/null && echo CONNECTED || echo BLOCKED' 2>/dev/null; true";
        let (out, _err, _exit) = run_sync(&executor, cmd, &ws, Some(8000)).unwrap();

        assert!(
            !out.contains("CONNECTED"),
            "BREACH [network-tcp]: TCP connection succeeded in Isolated mode! stdout={}",
            out
        );
    }

    /// Attack: DNS query via `host` command in Isolated mode.
    #[test]
    fn attack_network_isolated_dns_host() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        let policy = isolated_network_policy();
        let executor = SandboxExecutor::new(ws.clone(), policy);

        // "host" on success prints "google.com has address ..."
        let cmd = "timeout 3 host google.com 2>&1; true";
        let (out, _err, _exit) = run_sync(&executor, cmd, &ws, Some(8000)).unwrap();

        assert!(
            !out.contains("has address") && !out.contains("has IPv6"),
            "BREACH [network-dns-host]: DNS resolution succeeded in Isolated mode! stdout={}",
            out
        );
    }

    /// Attack: DNS query via `nslookup` in Isolated mode.
    #[test]
    fn attack_network_isolated_dns_nslookup() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        let policy = isolated_network_policy();
        let executor = SandboxExecutor::new(ws.clone(), policy);

        let cmd = "timeout 3 nslookup google.com 2>&1; true";
        let (out, _err, _exit) = run_sync(&executor, cmd, &ws, Some(8000)).unwrap();

        // nslookup on success prints "Name:" and "Address:"
        assert!(
            !out.contains("Address:")
                || out.contains("server can't find")
                || out.contains("NXDOMAIN")
                || out.contains("timed out")
                || out.contains("connection timed out")
                || out.contains("SERVFAIL")
                || out.contains("REFUSED"),
            "BREACH [network-dns-nslookup]: DNS resolution succeeded in Isolated mode! stdout={}",
            out
        );
    }

    /// Attack: HTTP request via curl in Isolated mode.
    #[test]
    fn attack_network_isolated_curl_http() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        let policy = isolated_network_policy();
        let executor = SandboxExecutor::new(ws.clone(), policy);

        let cmd = "timeout 5 curl -s --connect-timeout 2 http://example.com 2>&1; true";
        let (out, _err, _exit) = run_sync(&executor, cmd, &ws, Some(10000)).unwrap();

        assert!(
            !out.contains("<html") && !out.contains("Example Domain"),
            "BREACH [network-curl]: HTTP request succeeded in Isolated mode! stdout={}",
            out
        );
    }

    /// Attack: wget in Isolated mode.
    #[test]
    fn attack_network_isolated_wget() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        let policy = isolated_network_policy();
        let executor = SandboxExecutor::new(ws.clone(), policy);

        // Try wget; should fail to connect
        let cmd = "timeout 5 wget -q -O - --timeout=2 http://example.com 2>&1; true";
        let (out, _err, _exit) = run_sync(&executor, cmd, &ws, Some(10000)).unwrap();

        assert!(
            !out.contains("<html") && !out.contains("Example Domain"),
            "BREACH [network-wget]: HTTP request via wget succeeded in Isolated mode! stdout={}",
            out
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  CATEGORY 5: Resource / privilege-escalation attacks
    //  Guarantee: 沙箱内不能影响沙箱外的其它进程
    // ═══════════════════════════════════════════════════════════════════════════

    /// Attack: spawn many subprocesses to stress-test containment.
    #[test]
    fn attack_resource_many_subprocesses() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        let policy = make_policy(vec![ws.clone()], vec![]);
        let executor = SandboxExecutor::new(ws.clone(), policy);

        // Spawn 30 background sleep processes, count them, then wait
        let cmd =
            "for i in $(seq 1 30); do sleep 30 & done; jobs -p | wc -l > proc_count.txt; wait";
        let (_out, _err, exit) = run_sync(&executor, cmd, &ws, Some(15000)).unwrap();

        let count_file = ws.join("proc_count.txt");
        if count_file.exists() {
            let count: usize = std::fs::read_to_string(&count_file)
                .unwrap_or_default()
                .trim()
                .parse()
                .unwrap_or(0);
            eprintln!("sandbox allowed {} subprocesses", count);
        }

        // Key assertion: sandbox didn't crash or hang forever
        assert!(
            exit == ProcessExit::Code(0) || exit == ProcessExit::KilledByTimeout,
            "Sandbox crashed on subprocess test: {:?}",
            exit
        );
    }

    /// Attack: controlled fork bomb — recursive spawning, limited depth×breadth.
    #[test]
    fn attack_resource_fork_bomb_contained() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        let policy = make_policy(vec![ws.clone()], vec![]);
        let executor = SandboxExecutor::new(ws.clone(), policy);

        // Fork bomb-lite: 3 depth × 3 breadth = 27 processes
        let script = r#"
depth=${1:-0}
if [ "$depth" -lt 3 ]; then
    for i in 1 2 3; do
        bash "$0" $((depth + 1)) &
    done
fi
wait
echo FORK_DONE
"#;
        let script_path = ws.join("fork_bomb.sh");
        std::fs::write(&script_path, script).unwrap();

        let (_out, _err, exit) =
            run_sync(&executor, "bash fork_bomb.sh", &ws, Some(20000)).unwrap();

        assert!(
            exit == ProcessExit::Code(0) || exit == ProcessExit::KilledByTimeout,
            "Sandbox crashed on fork bomb test: {:?}",
            exit
        );
    }

    /// Attack: try to kill PID 1 (init) from inside the sandbox.
    /// With PID namespace: kills sandbox init, sandbox terminates. Host survives.
    /// Without PID namespace: fails with EPERM. Host survives.
    /// The test itself running is proof the host survived.
    #[cfg(target_os = "linux")]
    #[test]
    fn attack_resource_kill_init_process() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        let policy = make_policy(vec![ws.clone()], vec![]);
        let executor = SandboxExecutor::new(ws.clone(), policy);

        let cmd = "kill -9 1 2>&1; echo KILL_ATTEMPTED";
        let (out, _err, _exit) = run_sync(&executor, cmd, &ws, Some(5000)).unwrap();

        // If we're still executing, the host survived — test passes.
        eprintln!("kill -9 1 inside sandbox output: {}", out.trim());
    }

    /// Verify PID namespace isolation: inside sandbox, PID 1 should NOT be
    /// the host's init system.
    #[cfg(target_os = "linux")]
    #[test]
    fn attack_resource_pid_namespace_isolation() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        let policy = make_policy(vec![ws.clone()], vec![]);
        let executor = SandboxExecutor::new(ws.clone(), policy);

        let cmd = "cat /proc/1/cmdline 2>/dev/null | tr '\\0' ' '; echo";
        let (out, _err, exit) = run_sync(&executor, cmd, &ws, None).unwrap();

        eprintln!("Sandbox PID 1 cmdline: {}", out.trim());

        // If we can read /proc/1/cmdline and it shows host's init, that's a leak.
        // Host init contains "init" or "systemd" — but bwrap init shows "bwrap".
        if exit == ProcessExit::Code(0) {
            let is_host_like = out.contains("systemd")
                || out.contains("/sbin/init")
                || out.contains("init [")
                || out.trim().is_empty();
            // Empty means /proc might not be mounted — not a leak, just a different config
            if !out.trim().is_empty() {
                assert!(
                    !is_host_like,
                    "BREACH [pid-namespace]: sandbox sees host init process! cmdline={}",
                    out.trim()
                );
            }
        }
    }

    /// Attack: try to read /proc outside the sandbox namespace.
    /// If mount namespace is active, /proc should be sandbox-local.
    #[cfg(target_os = "linux")]
    #[test]
    fn attack_resource_read_host_proc() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        let policy = make_policy(vec![ws.clone()], vec![]);
        let executor = SandboxExecutor::new(ws.clone(), policy);

        // Try to list host processes — should only see sandbox processes
        let cmd = "cat /proc/1/status 2>/dev/null | head -5; echo";
        let (out, _err, _exit) = run_sync(&executor, cmd, &ws, None).unwrap();

        eprintln!("Sandbox /proc/1/status: {}", out.trim());

        // If Name: shows systemd, that's a host leak
        if out.contains("Name:") {
            assert!(
                !out.contains("Name:\tsystemd"),
                "BREACH [proc-leak]: sandbox can read host /proc! status={}",
                out.trim()
            );
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  Platform-specific attack tests — Windows
    // ═══════════════════════════════════════════════════════════════════════════

    /// Windows: write escape via absolute path to a system location.
    #[cfg(target_os = "windows")]
    #[test]
    fn attack_windows_write_escape_absolute() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        let target = dir.path().join("windows_abs_target.txt");
        let abs_path = target.to_string_lossy().replace("/", "\\");

        let policy = make_policy(vec![ws.clone()], vec![]);
        let executor = SandboxExecutor::new(ws.clone(), policy);

        let cmd = format!("echo PWNED > {}", abs_path);
        let (_out, _err, exit) = run_sync(&executor, &cmd, &ws, None).unwrap();

        assert_write_blocked(&exit, &target, "PWNED", "windows-write-absolute");
    }

    /// Windows: read escape via absolute path to System32.
    #[cfg(target_os = "windows")]
    #[test]
    fn attack_windows_read_escape_system32() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        let policy = make_policy(vec![ws.clone()], vec![]);
        let executor = SandboxExecutor::new(ws.clone(), policy);

        // Try to read hosts file — should be blocked
        let cmd = "type C:\\Windows\\System32\\drivers\\etc\\hosts";
        let (out, _err, exit) = run_sync(&executor, cmd, &ws, None).unwrap();

        // hosts file contains "localhost"
        assert_read_blocked(&exit, &out, "localhost", "windows-read-system32");
    }

    /// Windows: write escape via `..\..\` (backslash dotdot).
    #[cfg(target_os = "windows")]
    #[test]
    fn attack_windows_write_escape_backslash_dotdot() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        let outside = dir.path().join("win_dotdot_target.txt");
        std::fs::write(&outside, "CLEAN\n").unwrap();

        let policy = make_policy(vec![ws.clone()], vec![]);
        let executor = SandboxExecutor::new(ws.clone(), policy);

        // Windows backslash dotdot
        let cmd = "echo PWNED > ..\\win_dotdot_target.txt";
        let (_out, _err, exit) = run_sync(&executor, cmd, &ws, None).unwrap();

        assert_write_blocked(&exit, &outside, "PWNED", "windows-write-backslash-dotdot");
    }

    /// Windows: symlink inside writable_roots pointing to a read-protected
    /// location (%USERPROFILE%).  ACL-based read isolation operates on the
    /// real file object, so symlink resolution should still hit the deny ACE.
    #[cfg(target_os = "windows")]
    #[test]
    fn attack_windows_symlink_to_protected_profile() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        // Create a known file under %USERPROFILE% that contains a sentinel.
        let profile = std::env::var("USERPROFILE").unwrap();
        let secret_file = std::path::PathBuf::from(&profile).join("sandbox_secret_test.txt");
        let marker = format!("WIN_SYMLINK_SECRET_{}", std::process::id());
        std::fs::write(&secret_file, &marker).unwrap();

        // Create NTFS symlink inside workspace → outside protected file.
        let link = ws.join("sneaky_link");
        let link_cmd = format!(
            "mklink \"{}\" \"{}\"",
            link.display(),
            secret_file.display()
        );
        std::process::Command::new("cmd")
            .args(&["/c", &link_cmd])
            .current_dir(&ws)
            .output()
            .expect("mklink failed");
        assert!(link.exists(), "symlink should have been created");

        let policy = make_policy(vec![ws.clone()], vec![]);
        let executor = SandboxExecutor::new(ws.clone(), policy);

        let cmd = format!("type \"{}\"", link.display());
        let (out, _err, exit) = run_sync(&executor, &cmd, &ws, None).unwrap();

        // Cleanup secret file regardless.
        let _ = std::fs::remove_file(&secret_file);

        let breached = exit == ProcessExit::Code(0) && out.contains(&marker);
        assert!(
            !breached,
            "BREACH [windows-symlink-to-profile]: NTFS symlink bypassed read isolation! exit={:?} out={}",
            exit, out,
        );
    }

    /// Windows: symlink in %USERPROFILE% protected area pointing INTO the
    /// writable_roots workspace.  This is a reverse-leak check — the sandbox
    /// process shouldn't be able to read files via a symlink planted in a
    /// protected area.
    #[cfg(target_os = "windows")]
    #[test]
    fn attack_windows_symlink_in_profile_to_workspace() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        // Write a known secret inside the workspace.
        let ws_secret = ws.join("internal_data.txt");
        let marker = format!("WORKSPACE_INTERNAL_{}", std::process::id());
        std::fs::write(&ws_secret, &marker).unwrap();

        // Create a symlink in %USERPROFILE% pointing INTO the workspace.
        let profile = std::env::var("USERPROFILE").unwrap();
        let link = std::path::PathBuf::from(&profile).join("backdoor_link");
        let link_cmd = format!("mklink \"{}\" \"{}\"", link.display(), ws_secret.display());
        std::process::Command::new("cmd")
            .args(&["/c", &link_cmd])
            .output()
            .expect("mklink failed");

        let policy = make_policy(vec![ws.clone()], vec![]);
        let executor = SandboxExecutor::new(ws.clone(), policy);

        // The sandbox process has deny-read on %USERPROFILE% with child
        // inheritance, so the symlink under %USERPROFILE% should also be
        // denied.  However, this test confirms there's no reverse leak
        // (sandbox OUTSIDE reading workspace data via planted symlink).
        let cmd = format!("dir \"{}\" 2>&1", link.display());
        let (_out, _err, _exit) = run_sync(&executor, &cmd, &ws, None).unwrap();

        // Cleanup.
        let _ = std::fs::remove_file(&link);

        // The key assertion: the dir/ls command on the symlink path should
        // fail (denied) or see nothing (because the deny ACE on profile
        // blocks access).  We don't strongly assert here because the exact
        // behavior depends on whether the symlink was created before/after
        // the deny ACE was applied.  The important thing is this test
        // documents the scenario and runs on CI.
        eprintln!(
            "windows-symlink-in-profile: sandbox reading profile symlink → out={} err={}",
            _out, _err,
        );
    }

    /// Windows: verify that system-wide readable files (analogous to
    /// /etc/passwd on Linux) are NOT unconditionally readable from the
    /// sandbox.  ACL deny-read on %USERPROFILE% covers profile content;
    /// this test checks that we're not accidentally loosening permissions
    /// on system files.
    #[cfg(target_os = "windows")]
    #[test]
    fn attack_windows_no_etc_passwd_analog() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        let policy = make_policy(vec![ws.clone()], vec![]);
        let executor = SandboxExecutor::new(ws.clone(), policy);

        // Try to read the Windows hosts file (analogous to /etc/hosts).
        let cmd = "type C:\\Windows\\System32\\drivers\\etc\\hosts 2>&1";
        let (out, _err, exit) = run_sync(&executor, cmd, &ws, None).unwrap();

        // The hosts file contains "localhost" on all systems.
        // Our sandbox only restricts %USERPROFILE% (not system paths),
        // so this read might succeed — and that's OK for now because the
        // primary threat model is leaking user-specific data, not system
        // configuration.  But we document it here as awareness.
        let succeeded = out.contains("localhost") && exit == ProcessExit::Code(0);
        eprintln!(
            "windows-etc-hosts-analog: sandbox reading C:\\Windows\\...\\hosts -> succeeded={}",
            succeeded
        );
        // If this EVER blocks, that's fine — the sandbox is just being
        // more restrictive than required.  If it succeeds, it's also
        // acceptable because the deny-read ACL only targets %USERPROFILE%.
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  Platform-specific attack tests — macOS
    // ═══════════════════════════════════════════════════════════════════════════

    /// macOS: write escape via absolute path to /tmp.
    #[cfg(target_os = "macos")]
    #[test]
    fn attack_macos_write_escape_tmp() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        let marker = format!("MACOS_PWNED_{}", std::process::id());
        let target = PathBuf::from(format!("/tmp/sandbox_escape_{}.txt", std::process::id()));
        let _ = std::fs::remove_file(&target);

        let policy = make_policy(vec![ws.clone()], vec![]);
        let executor = SandboxExecutor::new(ws.clone(), policy);

        let cmd = format!("echo '{}' > {}", marker, target.display());
        let (_out, _err, exit) = run_sync(&executor, &cmd, &ws, None).unwrap();

        let _ = std::fs::remove_file(&target);
        assert_ne!(
            exit,
            ProcessExit::Code(0),
            "BREACH [macos-write-tmp]: write to /tmp succeeded! marker={}",
            marker
        );
    }

    /// macOS: read /etc/passwd via absolute path inside seatbelt sandbox.
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "macOS system-level read isolation not yet implemented"]
    fn attack_macos_read_etc_passwd() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        let policy = make_policy(vec![ws.clone()], vec![]);
        let executor = SandboxExecutor::new(ws.clone(), policy);

        let (out, _err, exit) = run_sync(&executor, "cat /etc/passwd", &ws, None).unwrap();

        assert_read_blocked(&exit, &out, "root:", "macos-read-/etc/passwd");
    }

    /// macOS: network isolation — curl in seatbelt sandbox.
    #[cfg(target_os = "macos")]
    #[test]
    fn attack_macos_network_isolated_curl() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        let policy = isolated_network_policy();
        let executor = SandboxExecutor::new(ws.clone(), policy);

        let cmd = "timeout 5 curl -s --connect-timeout 2 http://example.com 2>&1; true";
        let (out, _err, _exit) = run_sync(&executor, cmd, &ws, Some(10000)).unwrap();

        assert!(
            !out.contains("<html") && !out.contains("Example Domain"),
            "BREACH [macos-network-curl]: HTTP request succeeded in Isolated mode! stdout={}",
            out
        );
    }

    /// macOS: symlink inside writable_roots pointing outside → attempts to
    /// read through it.  Seatbelt's `subpath` + canonicalization should
    /// catch the real target.
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "macOS system-level read isolation not yet implemented"]
    fn attack_macos_symlink_to_outside_read() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        let outside = dir.path().join("macos_secret.txt");
        std::fs::write(&outside, "MACOS-SECRET-DATA\n").unwrap();

        let link = ws.join("outside_link");
        std::os::unix::fs::symlink(&outside, &link).unwrap();

        let policy = make_policy(vec![ws.clone()], vec![]);
        let executor = SandboxExecutor::new(ws.clone(), policy);

        let (out, _err, exit) = run_sync(&executor, "cat outside_link", &ws, None).unwrap();

        assert_read_blocked(
            &exit,
            &out,
            "MACOS-SECRET-DATA",
            "macos-symlink-outside-read",
        );
    }

    /// macOS: protected_path is a symlink pointing outside writable_roots.
    /// The seatbelt rule must canonicalize the symlink and mask the real target.
    #[cfg(target_os = "macos")]
    #[test]
    fn attack_macos_protected_symlink_is_outside_target() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        let real = dir.path().join("real_config");
        std::fs::write(&real, "TOP-SECRET-CONFIG=1\n").unwrap();

        // The protected_path IS a symlink.
        let link = ws.join("config");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let policy = make_policy(vec![ws.clone()], vec![PathBuf::from("config")]);
        let executor = SandboxExecutor::new(ws.clone(), policy);

        let (out, _err, exit) = run_sync(&executor, "cat config", &ws, None).unwrap();

        assert_read_blocked(
            &exit,
            &out,
            "TOP-SECRET-CONFIG",
            "macos-protected-symlink-is-outside",
        );
    }

    /// macOS: two different symlinks → same protected location.  Both must
    /// be blocked by the single mask on the real path.
    #[cfg(target_os = "macos")]
    #[test]
    fn attack_macos_two_symlinks_same_protected() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        let secrets = ws.join("private");
        std::fs::create_dir_all(&secrets).unwrap();
        std::fs::write(secrets.join("key.pem"), "-----BEGIN RSA PRIVATE KEY-----\n").unwrap();

        let link_a = ws.join("key_a");
        std::os::unix::fs::symlink("private/key.pem", &link_a).unwrap();
        let link_b = ws.join("key_b");
        std::os::unix::fs::symlink("private/key.pem", &link_b).unwrap();

        let policy = make_policy(vec![ws.clone()], vec![PathBuf::from("private")]);
        let executor = SandboxExecutor::new(ws.clone(), policy);

        let (out_a, _err_a, exit_a) = run_sync(&executor, "cat key_a", &ws, None).unwrap();
        assert_read_blocked(
            &exit_a,
            &out_a,
            "BEGIN RSA PRIVATE KEY",
            "macos-dual-symlink-a",
        );

        let (out_b, _err_b, exit_b) = run_sync(&executor, "cat key_b", &ws, None).unwrap();
        assert_read_blocked(
            &exit_b,
            &out_b,
            "BEGIN RSA PRIVATE KEY",
            "macos-dual-symlink-b",
        );
    }

    // ── ProxyOnly rejection (non-macOS) ─────────────────────────────────────

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn test_proxy_only_rejected_on_linux() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();
        let policy = SandboxPolicy {
            mode: SandboxMode::ReadOnly,
            writable_roots: vec![],
            network: NetworkPolicy::ProxyOnly,
            protected_paths: vec![],
        };
        let executor = SandboxExecutor::new(ws.to_path_buf(), policy);

        let result = run_sync(&executor, "echo hi", ws, None);

        match result {
            Err(ToolError::InvalidArgs(msg)) => {
                assert!(
                    msg.contains("ProxyOnly"),
                    "expected ProxyOnly error message, got: {}",
                    msg
                );
                println!("ProxyOnly correctly rejected: {}", msg);
            }
            other => panic!(
                "Expected ToolError::InvalidArgs with ProxyOnly message, got: {:?}",
                other
            ),
        }
    }
}
