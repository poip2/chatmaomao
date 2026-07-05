//! WriteTool — writes content to a file.

#![allow(dead_code)]
//!
//! Parameters (JSON):
//!   `path` (string, required)    — file path relative to the workspace root.
//!   `content` (string, required) — text to write.
//!
//! Parent directories are created automatically if they don't exist.
//!
//! Returns:
//!   AgentToolResult { content: confirmation, details: { path, size_bytes } }

use std::path::PathBuf;

use async_trait::async_trait;
use serde_json::json;

use crate::agent::types::{
    AgentContext, AgentSignal, AgentTool, AgentToolResult, StreamCallback, ToolDefinition,
    ToolError,
};

use super::validate_path;

/// Writes text content to a file, creating parent directories as needed.
pub struct WriteTool {
    cwd: PathBuf,
    protected_paths: Vec<PathBuf>,
}

impl WriteTool {
    pub fn new(ctx: &AgentContext) -> Self {
        Self {
            cwd: ctx.cwd.clone(),
            protected_paths: ctx.policy.protected_paths.clone(),
        }
    }
}

#[async_trait]
impl AgentTool for WriteTool {
    fn name(&self) -> &str {
        "write"
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

        let content = args
            .get("content")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidArgs("missing content argument".into()))?;

        let resolved = validate_path(path_str, &self.cwd, &self.protected_paths, false)?;

        // Create parent directories if needed
        if let Some(parent) = resolved.parent() {
            std::fs::create_dir_all(parent).map_err(ToolError::Io)?;
        }

        std::fs::write(&resolved, content).map_err(ToolError::Io)?;

        let size_bytes = content.len();

        Ok(AgentToolResult {
            content: format!("Successfully wrote {} bytes to {}", size_bytes, path_str),
            details: json!({
                "path": resolved.to_string_lossy(),
                "size_bytes": size_bytes,
            }),
        })
    }
}

impl ToolDefinition for WriteTool {
    fn description(&self) -> &str {
        "Write content to a file. Creates the file if it does not exist, \
         overwrites if it does. Parent directories are created automatically."
    }

    fn json_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the file to write, relative to the workspace root."
                },
                "content": {
                    "type": "string",
                    "description": "Text content to write to the file."
                }
            },
            "required": ["path", "content"]
        })
    }

    fn prompt_snippet(&self) -> &str {
        "Use `write` with `path` and `content` to create or overwrite a file."
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
    async fn test_write_new_file_success() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = make_ctx(&dir, vec![]);
        let tool = WriteTool::new(&ctx);

        let result = tool
            .execute(
                json!({"path": "out.md", "content": "# Hello\n"}),
                AgentSignal::new(),
                None,
            )
            .await
            .unwrap();

        assert!(result.content.contains("Successfully wrote"));
        assert_eq!(result.details["size_bytes"], 8);

        let written = std::fs::read_to_string(dir.path().join("out.md")).unwrap();
        assert_eq!(written, "# Hello\n");
    }

    #[tokio::test]
    async fn test_write_overwrite_existing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("existing.md"), "old\n").unwrap();

        let ctx = make_ctx(&dir, vec![]);
        let tool = WriteTool::new(&ctx);

        let result = tool
            .execute(
                json!({"path": "existing.md", "content": "new\n"}),
                AgentSignal::new(),
                None,
            )
            .await
            .unwrap();

        assert_eq!(result.details["size_bytes"], 4);
        let written = std::fs::read_to_string(dir.path().join("existing.md")).unwrap();
        assert_eq!(written, "new\n");
    }

    #[tokio::test]
    async fn test_write_outside_workspace_fails() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = make_ctx(&dir, vec![]);
        let tool = WriteTool::new(&ctx);

        let result = tool
            .execute(
                json!({"path": "../../etc/cant_write_here", "content": "bad"}),
                AgentSignal::new(),
                None,
            )
            .await;

        assert!(matches!(result, Err(ToolError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_write_protected_path_fails() {
        let dir = tempfile::tempdir().unwrap();
        // .git doesn't exist yet — protection should still block writes under it
        let ctx = make_ctx(&dir, vec![PathBuf::from(".git")]);
        let tool = WriteTool::new(&ctx);

        let result = tool
            .execute(
                json!({"path": ".git/config", "content": "[core]\n"}),
                AgentSignal::new(),
                None,
            )
            .await;

        assert!(
            matches!(result, Err(ToolError::SandboxDenied(_))),
            "expected SandboxDenied, got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_write_creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = make_ctx(&dir, vec![]);
        let tool = WriteTool::new(&ctx);

        let result = tool
            .execute(
                json!({"path": "a/b/c/deep.md", "content": "deep\n"}),
                AgentSignal::new(),
                None,
            )
            .await
            .unwrap();

        assert!(result.content.contains("Successfully wrote"));
        assert!(dir.path().join("a/b/c/deep.md").exists());
    }
}
