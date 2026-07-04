//! ReadTool — reads file contents and returns them to the LLM.
//!
//! Parameters (JSON):
//!   `path` (string, required) — file path relative to the workspace root.
//!
//! Returns:
//!   AgentToolResult { content: file contents, details: { path, size_bytes } }

use std::path::PathBuf;

use async_trait::async_trait;
use serde_json::json;

use crate::agent::types::{
    AgentContext, AgentSignal, AgentTool, AgentToolResult, StreamCallback, ToolDefinition,
    ToolError,
};

use super::validate_path;

/// Reads a file's contents and returns them as text.
pub struct ReadTool {
    cwd: PathBuf,
    protected_paths: Vec<PathBuf>,
}

impl ReadTool {
    pub fn new(ctx: &AgentContext) -> Self {
        Self {
            cwd: ctx.cwd.clone(),
            protected_paths: ctx.policy.protected_paths.clone(),
        }
    }
}

#[async_trait]
impl AgentTool for ReadTool {
    fn name(&self) -> &str {
        "read"
    }

    async fn execute(
        &self,
        args: serde_json::Value,
        signal: AgentSignal,
        _stream_callback: Option<StreamCallback>,
    ) -> Result<AgentToolResult, ToolError> {
        if signal.is_aborted() {
            return Err(ToolError::Cancelled);
        }

        let path_str = args
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidArgs("missing path argument".into()))?;

        let resolved = validate_path(path_str, &self.cwd, &self.protected_paths, true)?;

        let content = std::fs::read_to_string(&resolved).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ToolError::NotFound(format!("{}: {}", path_str, e))
            } else {
                ToolError::Io(e)
            }
        })?;

        let size_bytes = content.len();

        Ok(AgentToolResult {
            content,
            details: json!({
                "path": resolved.to_string_lossy(),
                "size_bytes": size_bytes,
            }),
        })
    }
}

impl ToolDefinition for ReadTool {
    fn description(&self) -> &str {
        "Read the contents of a file. Use this to examine files in the workspace."
    }

    fn json_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the file to read, relative to the workspace root."
                }
            },
            "required": ["path"]
        })
    }

    fn prompt_snippet(&self) -> &str {
        "Use `read` with a `path` parameter to read a file's contents."
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::types::{AgentContext, SandboxPolicy};
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    fn make_ctx(dir: &tempfile::TempDir, protected: Vec<PathBuf>) -> AgentContext {
        AgentContext {
            messages: vec![],
            queue: Arc::new(Mutex::new(VecDeque::new())),
            cwd: dir.path().to_path_buf(),
            policy: SandboxPolicy {
                protected_paths: protected,
                ..Default::default()
            },
        }
    }

    #[tokio::test]
    async fn test_read_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hello.txt"), "hello world\n").unwrap();

        let ctx = make_ctx(&dir, vec![]);
        let tool = ReadTool::new(&ctx);
        let result = tool
            .execute(json!({"path": "hello.txt"}), AgentSignal::new(), None)
            .await
            .unwrap();

        assert_eq!(result.content, "hello world\n");
        assert_eq!(
            result.details["path"].as_str().unwrap(),
            dir.path().join("hello.txt").to_string_lossy()
        );
        assert_eq!(result.details["size_bytes"], 12);
    }

    #[tokio::test]
    async fn test_read_outside_workspace_fails() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = make_ctx(&dir, vec![]);
        let tool = ReadTool::new(&ctx);

        let result = tool
            .execute(
                json!({"path": "../../etc/passwd"}),
                AgentSignal::new(),
                None,
            )
            .await;

        assert!(matches!(result, Err(ToolError::SandboxDenied(_))));
    }

    #[tokio::test]
    async fn test_read_protected_path_fails() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();
        std::fs::write(dir.path().join(".git/config"), "secret\n").unwrap();

        let ctx = make_ctx(&dir, vec![PathBuf::from(".git")]);
        let tool = ReadTool::new(&ctx);

        let result = tool
            .execute(
                json!({"path": ".git/config"}),
                AgentSignal::new(),
                None,
            )
            .await;

        assert!(matches!(result, Err(ToolError::SandboxDenied(_))));
    }

    #[tokio::test]
    async fn test_read_nonexistent_file_fails() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = make_ctx(&dir, vec![]);
        let tool = ReadTool::new(&ctx);

        let result = tool
            .execute(json!({"path": "nope.txt"}), AgentSignal::new(), None)
            .await;

        assert!(matches!(result, Err(ToolError::NotFound(_))));
    }
}
