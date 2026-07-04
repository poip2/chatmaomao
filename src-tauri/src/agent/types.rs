//! Core type definitions for the MaoMaoChat AI agent backend.
//!
//! These types scaffold the data model for an agent loop:
//! LLM streaming (text + tool calls) → tool execution → sandboxed bash/python →
//! result back to LLM. This file defines the type skeleton only — no business logic,
//! no sandbox implementation, no LLM integration, no Tauri commands.

// Allow dead_code for now — these types will be consumed in later steps.
#![allow(dead_code)]

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}, Mutex};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── SandboxPolicy ───────────────────────────────────────────────────────────────
// 对应伪代码：SandboxPolicy 结构体，定义工具（bash/python）的沙箱策略

/// Sandbox execution mode for tools (bash, python).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxMode {
    /// Tool can only read files; no writes anywhere.
    ReadOnly,
    /// Tool can write only within `writable_roots`.
    WorkspaceWrite,
    /// Tool has unrestricted access (equivalent to no sandbox).
    DangerFullAccess,
}

/// Network access policy inside the sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkPolicy {
    /// No network access at all.
    Isolated,
    /// Only allowed to connect through a local forwarding proxy.
    ProxyOnly,
    /// Full unfiltered network access.
    FullAccess,
}

/// Sandbox policy governing what a tool (bash/python) may access.
///
/// Applied per-tool-execution. The sandbox implementation (seatbelt/bwrap/landlock)
/// is NOT in this file — this is the policy data structure only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxPolicy {
    /// Execution mode: read-only, workspace-write, or unrestricted.
    pub mode: SandboxMode,
    /// Roots where writes are permitted (only meaningful in WorkspaceWrite mode).
    #[serde(default)]
    pub writable_roots: Vec<PathBuf>,
    /// Network access level.
    pub network: NetworkPolicy,
    /// Paths that are forced read-only even if inside `writable_roots` (e.g. .git).
    #[serde(default)]
    pub protected_paths: Vec<PathBuf>,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self {
            mode: SandboxMode::ReadOnly,
            writable_roots: vec![],
            network: NetworkPolicy::Isolated,
            protected_paths: vec![],
        }
    }
}

// ─── AgentSignal ─────────────────────────────────────────────────────────────────
// 对应伪代码：AgentSignal，取消信号，跨线程共享、可 clone、可调用 abort()

/// Cancellation signal for an agent loop iteration.
///
/// **Design choice**: Uses `Arc<AtomicBool>` instead of `tokio_util::sync::CancellationToken`.
///
/// *Reasoning*: At this stage the cancellation semantics are trivial (a single
/// boolean flag). `Arc<AtomicBool>` keeps the dependency footprint minimal, is
/// zero-cost to check, and the `Ordering::Relaxed` load/store is sufficient
/// since cancellation is a unidirectional "fire once" signal. If we later need
/// tree-structured cancellation or async `.cancelled()` futures, we can migrate
/// to `CancellationToken` without changing the public API — just the internals.
#[derive(Debug, Clone)]
pub struct AgentSignal {
    inner: Arc<AtomicBool>,
}

impl AgentSignal {
    /// Create a new signal in the non-aborted state.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Trigger cancellation. Idempotent — calling multiple times is safe.
    pub fn abort(&self) {
        self.inner.store(true, Ordering::Relaxed);
    }

    /// Check whether cancellation has been requested.
    pub fn is_aborted(&self) -> bool {
        self.inner.load(Ordering::Relaxed)
    }
}

impl Default for AgentSignal {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Message (placeholder) ───────────────────────────────────────────────────────
// 对应伪代码：Message 类型（占位 struct，后续步骤细化）

/// Placeholder for a chat message in the agent conversation history.
///
/// Fields are intentionally minimal; this will be fleshed out when the LLM
/// integration step defines the actual message schema (role, content, tool
/// calls, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Message role hint (e.g. "user", "assistant", "system", "tool").
    pub role: String,
    /// Message body.
    pub content: String,
}

// ─── AgentContext ────────────────────────────────────────────────────────────────
// 对应伪代码：AgentContext，单轮运行时状态

/// Steering command pushed into the agent's message queue from the UI layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SteeringMessage {
    /// Command name (e.g. "pause", "resume", "abort", "inject").
    pub command: String,
    /// Optional payload for the command.
    #[serde(default)]
    pub payload: serde_json::Value,
}

/// Per-turn runtime state for the agent loop.
pub struct AgentContext {
    /// Conversation history.
    pub messages: Vec<Message>,
    /// Thread-safe steering queue. The UI pushes `SteeringMessage` objects here;
    /// the agent loop polls them between LLM calls.
    pub queue: Arc<Mutex<VecDeque<SteeringMessage>>>,
    /// Current working directory for tool execution.
    pub cwd: PathBuf,
    /// Sandbox policy applied to tool executions in this turn.
    pub policy: SandboxPolicy,
}

// ─── ToolError ───────────────────────────────────────────────────────────────────
// 对应伪代码：ToolError 枚举，至少包含 NotFound | NotUnique | SandboxDenied |
//            Timeout | Cancelled | Io

/// Errors that can occur during tool execution.
#[derive(Debug, Error)]
pub enum ToolError {
    /// The requested file/resource was not found (e.g. read tool).
    #[error("not found: {0}")]
    NotFound(String),

    /// The target text was not unique in the file (e.g. edit tool's oldText).
    #[error("not unique: {0}")]
    NotUnique(String),

    /// The operation was denied by the sandbox policy.
    #[error("sandbox denied: {0}")]
    SandboxDenied(String),

    /// The tool execution timed out.
    #[error("timeout: {0}")]
    Timeout(String),

    /// The command exited with a non-zero exit code.
    #[error("non-zero exit code {0}: {1}")]
    NonZeroExit(i32, String),

    /// The tool was cancelled via AgentSignal.
    #[error("cancelled")]
    Cancelled,

    /// Invalid or missing arguments in the tool call.
    #[error("invalid arguments: {0}")]
    InvalidArgs(String),

    /// An I/O error occurred during tool execution.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// Placeholder for not-yet-implemented tools.
    #[error("not implemented")]
    NotImplemented,
}

// ─── AgentToolResult ─────────────────────────────────────────────────────────────
// 对应伪代码：AgentToolResult — content（给 LLM 看的文本）+ details（给 UI 的结构化数据）

/// Result of a single tool execution.
///
/// **Design choice for `details`**: Uses `serde_json::Value` as a universal
/// dynamically-typed container.
///
/// *Reasoning*: Different tools return different detail shapes (read → file
/// path + byte range, bash → exit code + stderr, etc.). A Rust-side enum with
/// one variant per tool would be closed (requires updating when adding tools)
/// and doesn't serialize well to the JS frontend. `serde_json::Value` is open,
/// immediately serializable to the Svelte UI layer without intermediate
/// transforms, and is the standard interop format in the Tauri/JS ecosystem.
/// The trade-off is losing compile-time exhaustiveness checking on the detail
/// shape — mitigated by each tool documenting its own detail schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentToolResult {
    /// Human-readable text summary for the LLM to consume.
    pub content: String,
    /// Structured data for the UI layer. Shape varies by tool; see each tool's
    /// documentation for its detail schema.
    #[serde(default)]
    pub details: serde_json::Value,
}

// ─── AgentTool trait ─────────────────────────────────────────────────────────────
// 对应伪代码：AgentTool — "薄"层，只保留 name + execute

/// Callback invoked by a tool during execution to push partial/streaming results
/// (e.g. stdout chunks from a long-running bash command).
pub type StreamCallback = Box<dyn Fn(String) + Send + Sync>;

/// The minimal tool interface: a name and an async execute method.
///
/// This is what the agent loop interacts with — it doesn't care about
/// descriptions, JSON schemas, or prompt snippets. Those belong to the thicker
/// [`ToolDefinition`] trait.
///
/// **Design choice for `async fn` in traits**: Uses the `#[async_trait]` macro
/// from the `async-trait` crate.
///
/// *Reasoning*: Rust's native async fn in traits (RPITIT, stabilized in 1.75)
/// still has ergonomic rough edges around `Send` bounds and dynamic dispatch.
/// The `async-trait` crate handles `Send + Sync` bounds automatically, produces
/// `Pin<Box<dyn Future>>` return types that work with `Arc<dyn AgentTool>`, and
/// is a well-established solution used across the Rust async ecosystem. The
/// trade-off is one extra heap allocation per call — negligible compared to LLM
/// latency. We can migrate to native RPITIT when the ecosystem matures.
#[async_trait]
pub trait AgentTool: Send + Sync {
    /// Unique tool name (e.g. "read", "write", "bash").
    fn name(&self) -> &str;

    /// Execute the tool.
    ///
    /// * `args` — JSON object with tool-specific parameters.
    /// * `signal` — cancellation token; the implementation should periodically
    ///   check `signal.is_aborted()` and short-circuit if set.
    /// * `stream_callback` — optional callback for pushing partial results
    ///   during long-running executions (e.g. stdout lines from bash).
    async fn execute(
        &self,
        args: serde_json::Value,
        signal: AgentSignal,
        stream_callback: Option<StreamCallback>,
    ) -> Result<AgentToolResult, ToolError>;
}

// ─── ToolDefinition trait ────────────────────────────────────────────────────────
// 对应伪代码：ToolDefinition — "厚"层，包含 name/description/JSON schema/prompt_snippet + execute

/// The full tool definition: everything an LLM and the UI need to know about a
/// tool, plus the execution logic.
///
/// **Relationship to [`AgentTool`]**: `ToolDefinition` is a supertrait of
/// `AgentTool`. A `ToolDefinition` *is* an `AgentTool` — it has the same
/// `name()` and `execute()` methods, plus extra metadata fields. The
/// [`wrap_tool_definition`] function strips the metadata layer when the agent
/// loop only needs the minimal interface.
#[async_trait]
pub trait ToolDefinition: AgentTool {
    /// Human-readable description of what the tool does (for the LLM).
    fn description(&self) -> &str;

    /// JSON Schema describing the tool's parameter shape.
    fn json_schema(&self) -> serde_json::Value;

    /// A snippet that can be injected into the system prompt to teach the LLM
    /// how to use this tool effectively.
    fn prompt_snippet(&self) -> &str;
}

/// Convert a full [`ToolDefinition`] into the minimal [`AgentTool`] interface.
///
/// This strips away description, JSON schema, and prompt snippet — only `name`
/// and `execute` remain. Useful when composing a tool registry for the agent loop
/// that doesn't need the full metadata.
///
/// **Implementation note**: Because Rust trait upcasting for `dyn` traits is
/// unstable, we cannot simply return `Arc<dyn AgentTool>` from an
/// `Arc<dyn ToolDefinition>`. Instead we create a thin wrapper struct that
/// delegates both methods to the inner definition.
///
/// *Design choice*: Wraps in a newtype rather than using trait upcasting.
/// *Reasoning*: `trait_upcasting` is nightly-only as of Rust 1.84. The wrapper
/// is zero-cost (the compiler inlines the delegation) and keeps the stable
/// toolchain requirement. `wrap_tool_definition` provides a canonical single
/// point of conversion; if trait upcasting stabilizes, only this function's
/// internals need to change.
pub fn wrap_tool_definition(def: Arc<dyn ToolDefinition>) -> Arc<dyn AgentTool> {
    Arc::new(ToolDefAsAgentTool(def))
}

/// Internal wrapper: adapts `Arc<dyn ToolDefinition>` → `Arc<dyn AgentTool>`.
struct ToolDefAsAgentTool(Arc<dyn ToolDefinition>);

#[async_trait]
impl AgentTool for ToolDefAsAgentTool {
    fn name(&self) -> &str {
        self.0.name()
    }

    async fn execute(
        &self,
        args: serde_json::Value,
        signal: AgentSignal,
        stream_callback: Option<StreamCallback>,
    ) -> Result<AgentToolResult, ToolError> {
        self.0.execute(args, signal, stream_callback).await
    }
}

// ─── Hook ───────────────────────────────────────────────────────────────────────
// 对应伪代码：Hook { blocked: bool, terminate: bool }

/// Result of a hook callback (before_tool_call / after_tool_call).
///
/// The agent loop checks this after invoking each hook:
/// - If `blocked` is true, the tool execution is skipped.
/// - If `terminate` is true, the entire agent loop is aborted.
#[derive(Debug, Clone, Copy, Default)]
pub struct Hook {
    /// If true, block this particular tool call from executing.
    pub blocked: bool,
    /// If true, terminate the entire agent loop iteration.
    pub terminate: bool,
}

// ─── AgentLoopConfig ─────────────────────────────────────────────────────────────
// 对应伪代码：AgentLoopConfig — 工具注册表 + system_prompt + before/after_tool_call

/// Signature for a hook that runs before or after a tool call.
///
/// Parameters:
/// - Tool name (`&str`)
/// - Tool arguments (`&serde_json::Value`)
///
/// Returns a [`Hook`] instructing the agent loop whether to block or terminate.
///
/// **Design choice**: Uses a boxed closure (`Arc<dyn Fn>`) rather than a trait.
///
/// *Reasoning*: These hooks are synchronous decision-making callbacks set up
/// during agent configuration. They don't need to be async (they answer simple
/// yes/no questions), and a boxed closure is the most ergonomic approach for
/// configuration-time use — callers can pass closures capturing their own
/// state, function pointers, or even no-ops. Wrapping in `Arc` makes the config
/// cheap to clone and share with the agent loop. A trait would be more verbose
/// without adding value at this stage. If we later need async hooks (e.g.
/// calling back to the frontend), we can replace this type alias with an
/// async-trait-based trait without changing the config field name.
pub type ToolCallHookFn = Arc<dyn Fn(&str, &serde_json::Value) -> Hook + Send + Sync>;

/// Configuration for a single run of the agent loop.
pub struct AgentLoopConfig {
    /// Tool registry: name → tool implementation.
    pub tools: HashMap<String, Arc<dyn AgentTool>>,
    /// The system prompt to send to the LLM.
    pub system_prompt: String,
    /// Callback invoked before each tool execution. If the hook returns
    /// `Hook { blocked: true, .. }`, the tool is skipped.
    pub before_tool_call: Option<ToolCallHookFn>,
    /// Callback invoked after each tool execution.
    pub after_tool_call: Option<ToolCallHookFn>,
}

// ─── Tests ───────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: verify all core types can be constructed.
    #[test]
    fn test_type_construction() {
        // SandboxPolicy
        let policy = SandboxPolicy {
            mode: SandboxMode::WorkspaceWrite,
            writable_roots: vec![PathBuf::from("/tmp/ws")],
            network: NetworkPolicy::ProxyOnly,
            protected_paths: vec![PathBuf::from("/tmp/ws/.git")],
        };
        assert_eq!(policy.mode, SandboxMode::WorkspaceWrite);
        assert!(!policy.writable_roots.is_empty());

        // AgentSignal
        let signal = AgentSignal::new();
        assert!(!signal.is_aborted());
        let signal2 = signal.clone();
        signal.abort();
        assert!(signal2.is_aborted());

        // AgentContext
        let ctx = AgentContext {
            messages: vec![Message {
                role: "user".into(),
                content: "hello".into(),
            }],
            queue: Arc::new(Mutex::new(VecDeque::new())),
            cwd: PathBuf::from("."),
            policy: SandboxPolicy::default(),
        };
        assert_eq!(ctx.messages.len(), 1);

        // Hook
        let hook = Hook { blocked: true, terminate: false };
        assert!(hook.blocked);
        assert!(!hook.terminate);

        // AgentLoopConfig
        let config = AgentLoopConfig {
            tools: HashMap::new(),
            system_prompt: "You are a helpful assistant.".into(),
            before_tool_call: None,
            after_tool_call: None,
        };
        assert_eq!(config.tools.len(), 0);
        assert!(!config.system_prompt.is_empty());
    }

    /// Verify that `wrap_tool_definition` compiles with the right types.
    /// Uses a minimal no-op tool definition that returns NotImplemented.
    #[test]
    fn test_wrap_tool_definition_signature() {
        struct NoopTool;

        #[async_trait]
        impl AgentTool for NoopTool {
            fn name(&self) -> &str { "noop" }

            async fn execute(
                &self,
                _args: serde_json::Value,
                _signal: AgentSignal,
                _stream_callback: Option<StreamCallback>,
            ) -> Result<AgentToolResult, ToolError> {
                Err(ToolError::NotImplemented)
            }
        }

        #[async_trait]
        impl ToolDefinition for NoopTool {
            fn description(&self) -> &str { "A no-op tool for testing." }
            fn json_schema(&self) -> serde_json::Value {
                serde_json::json!({"type": "object"})
            }
            fn prompt_snippet(&self) -> &str { "" }
        }

        let def: Arc<dyn ToolDefinition> = Arc::new(NoopTool);
        let tool: Arc<dyn AgentTool> = wrap_tool_definition(def);

        assert_eq!(tool.name(), "noop");

        // Verify the wrapper delegates execute correctly (returns NotImplemented).
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(tool.execute(
            serde_json::json!({}),
            AgentSignal::new(),
            None,
        ));
        assert!(matches!(result, Err(ToolError::NotImplemented)));
    }
}
