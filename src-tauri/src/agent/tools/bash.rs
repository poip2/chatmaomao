//! BashTool — executes shell commands and returns their output.
//!
//! Architecture:
//!   `BashTool` (accumulation, throttling, truncation, formatting)
//!       │
//!       ▼
//!   `ProcessExecutor` trait  ←── pluggable backend
//!       │
//!       ▼
//!   `LocalExecutor` (direct spawn, no sandbox — this step)
//!       │  (step 4: SandboxExecutor wraps seatbelt/bwrap here)
//!
//! Parameters (JSON):
//!   `command`  (string, required) — shell command to run.
//!   `timeout_ms` (number, optional) — timeout in milliseconds.
//!
//! Returns:
//!   AgentToolResult {
//!     content: truncated output text,
//!     details: { exit_code, stdout_size, truncated, full_output_path, killed }
//!   }

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde_json::json;

use crate::agent::types::{
    AgentContext, AgentSignal, AgentTool, AgentToolResult, StreamCallback, ToolDefinition,
    ToolError,
};

// ─── Constants ───────────────────────────────────────────────────────────────────

const MAX_OUTPUT_LINES: usize = 2000;
const MAX_OUTPUT_BYTES: usize = 200_000;
const THROTTLE_MS: u64 = 100;

// ─── ProcessExit ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessExit {
    Code(i32),
    KilledByTimeout,
    KilledByCancel,
}

// ─── OutputHandler trait ─────────────────────────────────────────────────────────

/// Lightweight callback trait for stdout/stderr chunks.
///
/// We use a custom trait instead of `dyn Fn(&[u8])` because the latter has a
/// Higher-Ranked Trait Bound (`for<'a> Fn(&'a [u8])`) that Rust's lifetime
/// inference frequently narrows to a concrete lifetime in `async fn` arguments.
/// A method `handle(&self, data: &[u8])` avoids this — the `data` lifetime is
/// inferred at each call site independently, so it works naturally inside
/// `tokio::select!` and async blocks.
pub trait OutputHandler: Send + Sync + 'static {
    fn handle(&self, data: &[u8]);
}

// Blanket impl so any compatible closure works without manual wrapping.
impl<F: Fn(&[u8]) + Send + Sync + 'static> OutputHandler for F {
    fn handle(&self, data: &[u8]) {
        (self)(data);
    }
}

// ─── ProcessExecutor trait ───────────────────────────────────────────────────────

/// Pluggable backend for executing shell commands.
///
/// **MUST** (these are not optional):
/// - Read stdout and stderr concurrently.
/// - Kill the entire process tree on timeout/cancel.
/// - Wait for the **process** to exit, not for streams to close.
///
/// **Step 4 sandbox integration**: write a `SandboxExecutor` that wraps the child
/// in seatbelt (macOS) / bwrap+landlock (Linux), implementing this same trait.
/// `BashTool` only depends on `ProcessExecutor`, so no BashTool changes needed.
#[async_trait]
pub trait ProcessExecutor: Send + Sync {
    /// Run a shell command, calling `on_stdout` / `on_stderr` for each output chunk.
    async fn run(
        &self,
        command: &str,
        cwd: &Path,
        timeout_ms: Option<u64>,
        signal: AgentSignal,
        on_stdout: Arc<dyn OutputHandler>,
        on_stderr: Arc<dyn OutputHandler>,
    ) -> Result<ProcessExit, ToolError>;
}

// ─── LocalExecutor ───────────────────────────────────────────────────────────────

pub struct LocalExecutor;

impl LocalExecutor {
    pub fn new() -> Self {
        Self
    }
}

/// Data chunk sent from a pipe-reader task to the main loop.
enum PipeChunk {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
}

#[async_trait]
impl ProcessExecutor for LocalExecutor {
    async fn run(
        &self,
        command: &str,
        cwd: &Path,
        timeout_ms: Option<u64>,
        signal: AgentSignal,
        on_stdout: Arc<dyn OutputHandler>,
        on_stderr: Arc<dyn OutputHandler>,
    ) -> Result<ProcessExit, ToolError> {
        let (shell, shell_arg) = if cfg!(unix) {
            ("sh", "-c")
        } else {
            ("cmd", "/c")
        };

        let mut std_cmd = std::process::Command::new(shell);
        std_cmd
            .arg(shell_arg)
            .arg(command)
            .current_dir(cwd)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

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
            .map_err(|e| ToolError::Io(e))?;

        let pid = child.id().expect("child must have a PID");
        let child_stdout = child.stdout.take().expect("stdout piped");
        let child_stderr = child.stderr.take().expect("stderr piped");

        // ── Channel from reader tasks → main loop ──
        let (chunk_tx, mut chunk_rx) =
            tokio::sync::mpsc::unbounded_channel::<PipeChunk>();
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
        // `tokio::pin!` lets us poll these across loop iterations.
        let child_wait = child.wait();
        tokio::pin!(child_wait);

        let timeout_sleep = timeout_ms
            .map(|ms| tokio::time::sleep(Duration::from_millis(ms)))
            .unwrap_or_else(|| tokio::time::sleep(Duration::MAX));
        tokio::pin!(timeout_sleep);

        let cancel_poll = cancel_watcher(signal);
        tokio::pin!(cancel_poll);

        // ── Main event loop ──
        // Each select! arm clones on_stdout / on_stderr Arcs into an
        // async move block so that the spawned future owns a 'static-
        // bound copy, avoiding the classic tokio::spawn + reference
        // lifetime conflict across select! branches.
        loop {
            tokio::select! {
                // ── stdout / stderr chunk ──
                Some(chunk) = chunk_rx.recv() => {
                    match chunk {
                        PipeChunk::Stdout(data) => on_stdout.handle(&data),
                        PipeChunk::Stderr(data) => on_stderr.handle(&data),
                    }
                }

                // ── Process exited normally ──
                status = &mut child_wait => {
                    reader_done.store(true, Ordering::Relaxed);
                    drain_channels(chunk_rx, on_stdout.clone(), on_stderr.clone()).await;
                    return match status {
                        Ok(s) => Ok(ProcessExit::Code(s.code().unwrap_or(1))),
                        Err(e) => Err(ToolError::Io(e)),
                    };
                }

                // ── Timeout ──
                _ = &mut timeout_sleep => {
                    kill_process_tree(pid);
                    let _ = (&mut child_wait).await;
                    reader_done.store(true, Ordering::Relaxed);
                    drain_channels(chunk_rx, on_stdout.clone(), on_stderr.clone()).await;
                    return Ok(ProcessExit::KilledByTimeout);
                }

                // ── Cancel ──
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

/// Async future that resolves when the AgentSignal is aborted.
async fn cancel_watcher(signal: AgentSignal) {
    loop {
        if signal.is_aborted() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Drain any data already buffered in the channel after the process exits.
/// Takes ownership of the receiver and callbacks via Arc::clone so the
/// spawned select! future satisfies the 'static bound.
/// Uses a 200 ms deadline so we don't block on data from detached grandchildren.
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

/// Spawn a tokio task that reads from a child's stdout/stderr pipe and sends
/// chunks through the channel.  Stops when the pipe closes (EOF) or when
/// `done` is set (process exited, no need to keep reading).
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

// ─── Process-tree kill ───────────────────────────────────────────────────────────

/// Kill the process and all its descendants.
///
/// **Unix**: `process_group(0)` made the child a process-group leader with
/// PGID == PID.  `kill(-PGID, SIGKILL)` delivers the signal to every process
/// in the group (the shell + children + grandchildren started without `setsid`).
///
/// **Windows**: `taskkill /PID <pid> /T /F` kills the process and its entire
/// descendant tree.
fn kill_process_tree(pid: u32) {
    #[cfg(unix)]
    {
        let pgid = pid as i32;
        unsafe {
            // Negative pid means "process group" in kill(2).
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

// ─── BashTool ────────────────────────────────────────────────────────────────────

/// Shell command execution tool.
///
/// Owns output accumulation, throttling, truncation, and error formatting.
/// Delegates actual process management to `ProcessExecutor`.
pub struct BashTool {
    executor: Arc<dyn ProcessExecutor>,
    cwd: PathBuf,
}

impl BashTool {
    pub fn new(executor: Arc<dyn ProcessExecutor>, ctx: &AgentContext) -> Self {
        Self {
            executor,
            cwd: ctx.cwd.clone(),
        }
    }
}

#[async_trait]
impl AgentTool for BashTool {
    fn name(&self) -> &str {
        "bash"
    }

    async fn execute(
        &self,
        args: serde_json::Value,
        signal: AgentSignal,
        stream_callback: Option<StreamCallback>,
    ) -> Result<AgentToolResult, ToolError> {
        let command = args
            .get("command")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::NotFound("missing 'command' argument".into()))?;

        let timeout_ms = args.get("timeout_ms").and_then(|v| v.as_u64());

        // ── Shared accumulation state ──
        let output: Arc<std::sync::Mutex<Vec<u8>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let last_emit: Arc<std::sync::Mutex<Instant>> =
            Arc::new(std::sync::Mutex::new(Instant::now()));
        let was_truncated: Arc<std::sync::Mutex<bool>> =
            Arc::new(std::sync::Mutex::new(false));
        let line_count: Arc<std::sync::Mutex<usize>> =
            Arc::new(std::sync::Mutex::new(0));
        let stream_cb: Arc<std::sync::Mutex<Option<StreamCallback>>> =
            Arc::new(std::sync::Mutex::new(stream_callback));

        // ── Build output callbacks ──
        let make_cb = |label: &'static str| {
            let output = output.clone();
            let last_emit = last_emit.clone();
            let was_truncated = was_truncated.clone();
            let line_count = line_count.clone();
            let stream_cb = stream_cb.clone();
            let cb: Arc<dyn OutputHandler> = Arc::new(move |data: &[u8]| {
                let mut out = output.lock().unwrap();
                let mut lc = line_count.lock().unwrap();

                *lc += data.iter().filter(|&&b| b == b'\n').count();
                if out.len() > MAX_OUTPUT_BYTES || *lc > MAX_OUTPUT_LINES {
                    *was_truncated.lock().unwrap() = true;
                }
                out.extend_from_slice(data);

                // ── 100 ms heartbeat throttle ──
                let now = Instant::now();
                let mut last = last_emit.lock().unwrap();
                if now.duration_since(*last) >= Duration::from_millis(THROTTLE_MS) {
                    *last = now;
                    if let Some(ref cb) = *stream_cb.lock().unwrap() {
                        let text = String::from_utf8_lossy(data).to_string();
                        if !text.is_empty() {
                            let prefix =
                                if label == "stderr" { "[stderr] " } else { "" };
                            cb(format!("{}{}", prefix, text));
                        }
                    }
                }
            });
            cb
        };

        // ── Execute ──
        let exit = self
            .executor
            .run(command, &self.cwd, timeout_ms, signal, make_cb("stdout"), make_cb("stderr"))
            .await?;

        // ── Format result ──
        let full_output = {
            String::from_utf8_lossy(&output.lock().unwrap()).to_string()
        };
        let output_len = full_output.len();
        let truncated = *was_truncated.lock().unwrap();

        let (content, full_output_path) = if truncated {
            let tmp = write_full_to_temp(&full_output)?;
            let truncated_text = truncate_output(&full_output);
            (truncated_text, Some(tmp))
        } else {
            (full_output, None)
        };

        match exit {
            ProcessExit::Code(code) if code != 0 => Err(ToolError::SandboxDenied(format!(
                "command exited with code {}: {}",
                code, command
            ))),
            ProcessExit::KilledByTimeout => Err(ToolError::Timeout(format!(
                "command timed out: {}", command
            ))),
            ProcessExit::KilledByCancel => Err(ToolError::Cancelled),
            ProcessExit::Code(_) => Ok(AgentToolResult {
                content,
                details: json!({
                    "exit_code": 0,
                    "stdout_size": output_len,
                    "truncated": truncated,
                    "full_output_path": full_output_path,
                    "killed": false,
                }),
            }),
        }
    }
}

impl ToolDefinition for BashTool {
    fn description(&self) -> &str {
        "Execute a shell command and return its output. Use for file operations, \
         git commands, building, testing, and any other shell tasks."
    }

    fn json_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "command": { "type": "string", "description": "The shell command to execute." },
                "timeout_ms": { "type": "number", "description": "Optional timeout in milliseconds." }
            },
            "required": ["command"]
        })
    }

    fn prompt_snippet(&self) -> &str {
        "Use `bash` with a `command` parameter to run shell commands. \
         The command runs in the workspace directory."
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────────

fn truncate_output(full: &str) -> String {
    let lines: Vec<&str> = full.lines().collect();
    if lines.len() <= MAX_OUTPUT_LINES {
        return full.to_string();
    }
    let start = lines.len() - MAX_OUTPUT_LINES;
    format!(
        "[output truncated: {} lines → showing last {} lines]\n{}",
        lines.len(),
        MAX_OUTPUT_LINES,
        lines[start..].join("\n")
    )
}

fn write_full_to_temp(full: &str) -> Result<String, ToolError> {
    let mut tmp = tempfile::NamedTempFile::new().map_err(|e| ToolError::Io(e))?;
    std::io::Write::write_all(&mut tmp, full.as_bytes())
        .map_err(|e| ToolError::Io(e))?;
    let path = tmp.into_temp_path();
    let s = path.to_string_lossy().to_string();
    path.keep().map_err(|e| ToolError::Io(e.into()))?;
    Ok(s)
}

// ─── Tests ───────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::types::{AgentContext, SandboxPolicy};
    use std::collections::VecDeque;
    use std::sync::Mutex;

    fn make_ctx(dir: &tempfile::TempDir) -> AgentContext {
        AgentContext {
            messages: vec![],
            queue: Arc::new(Mutex::new(VecDeque::new())),
            cwd: dir.path().to_path_buf(),
            policy: SandboxPolicy::default(),
        }
    }

    fn make_tool(dir: &tempfile::TempDir) -> BashTool {
        let ctx = make_ctx(dir);
        BashTool::new(Arc::new(LocalExecutor::new()), &ctx)
    }

    // ── 1. basic execution ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_simple_echo() {
        let dir = tempfile::tempdir().unwrap();
        let tool = make_tool(&dir);
        let r = tool
            .execute(json!({"command": "echo hello world"}), AgentSignal::new(), None)
            .await
            .unwrap();
        assert!(r.content.contains("hello world"));
        assert_eq!(r.details["exit_code"], 0);
    }

    // ── 2. non-zero exit code ≠ timeout/cancel ──────────────────────────────

    #[tokio::test]
    async fn test_exit_code_nonzero() {
        let dir = tempfile::tempdir().unwrap();
        let tool = make_tool(&dir);
        let r = tool
            .execute(json!({"command": "exit 42"}), AgentSignal::new(), None)
            .await;
        match r {
            Err(ToolError::SandboxDenied(msg)) => {
                assert!(msg.contains("42"), "{}", msg);
            }
            other => panic!("expected SandboxDenied, got {:?}", other),
        }
    }

    // ── 3. truncation ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_truncation_3000_lines() {
        let dir = tempfile::tempdir().unwrap();
        let tool = make_tool(&dir);
        let cmd = "for i in $(seq 1 3000); do echo \"line $i\"; done";
        let r = tool
            .execute(json!({"command": cmd}), AgentSignal::new(), None)
            .await
            .unwrap();

        assert_eq!(r.details["truncated"], true);
        assert!(r.content.contains("[output truncated"));
        assert!(r.content.contains("line 3000"), "last line present");
        assert!(!r.content.contains("line 1\n"), "first line truncated");
        assert_eq!(r.details["killed"], false);

        let path = r.details["full_output_path"].as_str().unwrap();
        let full = std::fs::read_to_string(path).unwrap();
        assert_eq!(full.lines().count(), 3000, "full file has 3000 lines");
        assert!(full.contains("line 1"), "full file has line 1");
        std::fs::remove_file(path).unwrap();
    }

    // ── 4. timeout + process really dead ────────────────────────────────────

    #[tokio::test]
    async fn test_timeout_kills_process() {
        let dir = tempfile::tempdir().unwrap();
        let tool = make_tool(&dir);

        // Command: save PID to a temp file, then sleep. After timeout,
        // we use the saved PID to verify with kill -0 that the process is gone.
        let pid_file = dir.path().join("test.pid");
        let pf = pid_file.to_string_lossy().to_string();
        let cmd = format!("echo $$ > {}; exec sleep 60", pf);

        let r = tool
            .execute(
                json!({"command": cmd, "timeout_ms": 500}),
                AgentSignal::new(),
                None,
            )
            .await;

        assert!(matches!(r, Err(ToolError::Timeout(_))), "got {:?}", r);

        // Read the PID that the shell wrote before exec'ing sleep.
        let pid_str = std::fs::read_to_string(&pid_file).unwrap();
        let pid: i32 = pid_str.trim().parse().unwrap();

        // kill -0 checks if the process exists (returns 0 if alive, non-zero if not).
        #[cfg(unix)]
        {
            let alive = unsafe { libc::kill(pid, 0) == 0 };
            assert!(!alive, "process {} should be dead", pid);
        }
    }

    // ── 5. cancel + process really dead ─────────────────────────────────────

    #[tokio::test]
    async fn test_cancel_kills_process() {
        let dir = tempfile::tempdir().unwrap();
        let tool = make_tool(&dir);
        let signal = AgentSignal::new();

        let pid_file = dir.path().join("cancel.pid");
        let pf = pid_file.to_string_lossy().to_string();
        let cmd = format!("echo $$ > {}; exec sleep 60", pf);

        let s = signal.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            s.abort();
        });

        let r = tool.execute(json!({"command": cmd}), signal, None).await;

        assert!(matches!(r, Err(ToolError::Cancelled)), "got {:?}", r);

        #[cfg(unix)]
        {
            let pid_str = std::fs::read_to_string(&pid_file).unwrap();
            let pid: i32 = pid_str.trim().parse().unwrap();
            let alive = unsafe { libc::kill(pid, 0) == 0 };
            assert!(!alive, "process {} should be dead", pid);
        }
    }

    // ── 6. process tree kill ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_kills_process_tree() {
        let dir = tempfile::tempdir().unwrap();
        let tool = make_tool(&dir);

        // Save shell PID + child PIDs, then test they're all dead after kill.
        let pid_file = dir.path().join("tree.pid");
        let pf = pid_file.to_string_lossy().to_string();
        let cmd = format!(
            "echo $$ > {pf}; sleep 100 & echo $! >> {pf}; sleep 100 & echo $! >> {pf}; wait",
            pf = pf
        );

        let r = tool
            .execute(
                json!({"command": cmd, "timeout_ms": 500}),
                AgentSignal::new(),
                None,
            )
            .await;

        assert!(matches!(r, Err(ToolError::Timeout(_))), "got {:?}", r);

        #[cfg(unix)]
        {
            let content = std::fs::read_to_string(&pid_file).unwrap();
            for line in content.lines() {
                let pid: i32 = line.trim().parse().unwrap();
                let alive = unsafe { libc::kill(pid, 0) == 0 };
                assert!(!alive, "process {} should be dead", pid);
            }
        }
    }

    // ── 7. detached grandchild does NOT block return ────────────────────────

    #[tokio::test]
    async fn test_detached_grandchild_does_not_block() {
        let dir = tempfile::tempdir().unwrap();
        let tool = make_tool(&dir);

        // `(sleep 100 &); echo done` — the background grandchild inherits
        // stdout/stderr FDs.  The shell exits immediately after `echo done`.
        // If we waited on stream EOF we would hang forever.  We wait on
        // `child.wait()` instead, so "done" must appear in the result.
        let r = tool
            .execute(
                json!({"command": "(sleep 100 &); echo done"}),
                AgentSignal::new(),
                None,
            )
            .await
            .unwrap();

        assert!(r.content.contains("done"), "got: {}", r.content);
    }

    // ── 8. concurrent stdout/stderr (no deadlock) ───────────────────────────

    #[tokio::test]
    async fn test_concurrent_stdout_stderr() {
        let dir = tempfile::tempdir().unwrap();
        let tool = make_tool(&dir);

        // 1000 iterations of interleaved stdout + stderr.  Sequential reads
        // would deadlock when one pipe buffer fills up.
        let cmd = "for i in $(seq 1 1000); do echo \"out$i\"; echo \"err$i\" >&2; done";
        let r = tool
            .execute(json!({"command": cmd}), AgentSignal::new(), None)
            .await
            .unwrap();

        assert!(r.content.contains("out500"));
        assert!(r.content.contains("err500"));
        assert!(r.content.contains("out1000"));
        assert!(r.content.contains("err1000"));
    }

    // ── 9. stream callback fires multiple times (throttle) ──────────────────

    #[tokio::test]
    async fn test_stream_callback_multiple_calls() {
        let dir = tempfile::tempdir().unwrap();
        let tool = make_tool(&dir);

        let hits: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
        let h = hits.clone();
        let cb: StreamCallback = Box::new(move |chunk| {
            h.lock().unwrap().push(chunk);
        });

        // 5 iterations with small sleeps → multiple throttle ticks.
        let cmd = "for i in $(seq 1 5); do echo \"chunk$i\"; sleep 0.05; done";
        tool.execute(json!({"command": cmd}), AgentSignal::new(), Some(cb))
            .await
            .unwrap();

        let calls = hits.lock().unwrap();
        assert!(calls.len() >= 2, "stream callback called {} times", calls.len());
    }
}
