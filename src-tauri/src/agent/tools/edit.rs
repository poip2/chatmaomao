//! EditTool — performs exact string replacement in a file.
//!
//! Parameters (JSON):
//!   `path` (string, required)       — file path relative to the workspace root.
//!   `old_string` (string, required) — exact text to search for.
//!   `new_string` (string, required) — replacement text.
//!
//! Behaviour:
//!   - 0 occurrences of `old_string` → Err(ToolError::NotFound)
//!   - 1 occurrence                   → replace and write back
//!   - 2+ occurrences                → Err(ToolError::NotUnique)
//!
//! Returns:
//!   AgentToolResult { content: confirmation, details: { path, replacements } }

use std::path::PathBuf;

use async_trait::async_trait;
use serde_json::json;

use crate::agent::types::{
    AgentContext, AgentSignal, AgentTool, AgentToolResult, StreamCallback, ToolDefinition,
    ToolError,
};

use super::validate_path;

/// Performs a single exact-string replacement in a file.
pub struct EditTool {
    cwd: PathBuf,
    protected_paths: Vec<PathBuf>,
}

impl EditTool {
    pub fn new(ctx: &AgentContext) -> Self {
        Self {
            cwd: ctx.cwd.clone(),
            protected_paths: ctx.policy.protected_paths.clone(),
        }
    }
}

#[async_trait]
impl AgentTool for EditTool {
    fn name(&self) -> &str {
        "edit"
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

        let old_string = args
            .get("old_string")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidArgs("missing old_string argument".into()))?;

        let new_string = args
            .get("new_string")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidArgs("missing new_string argument".into()))?;

        let resolved = validate_path(path_str, &self.cwd, &self.protected_paths, true)?;

        let content = std::fs::read_to_string(&resolved).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ToolError::NotFound(format!("{}: {}", path_str, e))
            } else {
                ToolError::Io(e)
            }
        })?;

        let count = content.matches(old_string).count();

        match count {
            0 => Err(ToolError::NotFound(format!(
                "old_string not found in {}",
                path_str
            ))),
            1 => {
                let new_content = content.replacen(old_string, new_string, 1);
                std::fs::write(&resolved, &new_content).map_err(|e| ToolError::Io(e))?;

                Ok(AgentToolResult {
                    content: format!(
                        "Successfully edited {}: replaced 1 occurrence of old_string.",
                        path_str
                    ),
                    details: json!({
                        "path": resolved.to_string_lossy(),
                        "replacements": 1,
                    }),
                })
            }
            n => Err(ToolError::NotUnique(format!(
                "old_string appears {} times in {}; must appear exactly once",
                n, path_str
            ))),
        }
    }
}

impl ToolDefinition for EditTool {
    fn description(&self) -> &str {
        "Make an exact string replacement in a file. The old_string must appear \
         exactly once in the file; otherwise the edit is rejected."
    }

    fn json_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the file to edit, relative to the workspace root."
                },
                "old_string": {
                    "type": "string",
                    "description": "The exact text to replace."
                },
                "new_string": {
                    "type": "string",
                    "description": "The text to insert in place of old_string."
                }
            },
            "required": ["path", "old_string", "new_string"]
        })
    }

    fn prompt_snippet(&self) -> &str {
        "Use `edit` with `path`, `old_string`, and `new_string` to make a single \
         exact-string replacement. The old_string must be unique in the file."
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
    async fn test_edit_single_occurrence_success() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("doc.md"), "# Title\n\nHello world.\n").unwrap();

        let ctx = make_ctx(&dir, vec![]);
        let tool = EditTool::new(&ctx);

        let result = tool
            .execute(
                json!({
                    "path": "doc.md",
                    "old_string": "Hello world.",
                    "new_string": "Goodbye world."
                }),
                AgentSignal::new(),
                None,
            )
            .await
            .unwrap();

        assert!(result.content.contains("Successfully edited"));
        assert_eq!(result.details["replacements"], 1);

        let updated = std::fs::read_to_string(dir.path().join("doc.md")).unwrap();
        assert!(updated.contains("Goodbye world."));
        assert!(!updated.contains("Hello world."));
    }

    #[tokio::test]
    async fn test_edit_zero_occurrences_fails() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("doc.md"), "# Title\n").unwrap();

        let ctx = make_ctx(&dir, vec![]);
        let tool = EditTool::new(&ctx);

        let result = tool
            .execute(
                json!({
                    "path": "doc.md",
                    "old_string": "nonexistent text",
                    "new_string": "replacement"
                }),
                AgentSignal::new(),
                None,
            )
            .await;

        assert!(matches!(result, Err(ToolError::NotFound(_))));

        // File should be unchanged
        let content = std::fs::read_to_string(dir.path().join("doc.md")).unwrap();
        assert_eq!(content, "# Title\n");
    }

    #[tokio::test]
    async fn test_edit_multiple_occurrences_fails() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("doc.md"), "foo bar foo baz foo\n").unwrap();

        let ctx = make_ctx(&dir, vec![]);
        let tool = EditTool::new(&ctx);

        let result = tool
            .execute(
                json!({
                    "path": "doc.md",
                    "old_string": "foo",
                    "new_string": "qux"
                }),
                AgentSignal::new(),
                None,
            )
            .await;

        match result {
            Err(ToolError::NotUnique(ref msg)) => {
                assert!(msg.contains("3 times"), "expected '3 times', got: {}", msg);
            }
            other => panic!("expected NotUnique, got {:?}", other),
        }

        // File should remain unchanged
        let content = std::fs::read_to_string(dir.path().join("doc.md")).unwrap();
        assert_eq!(content, "foo bar foo baz foo\n");
    }

    #[tokio::test]
    async fn test_edit_nonexistent_file_fails() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = make_ctx(&dir, vec![]);
        let tool = EditTool::new(&ctx);

        let result = tool
            .execute(
                json!({
                    "path": "nope.md",
                    "old_string": "x",
                    "new_string": "y"
                }),
                AgentSignal::new(),
                None,
            )
            .await;

        assert!(matches!(result, Err(ToolError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_edit_outside_workspace_fails() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = make_ctx(&dir, vec![]);
        let tool = EditTool::new(&ctx);

        let result = tool
            .execute(
                json!({
                    "path": "../../etc/passwd",
                    "old_string": "root",
                    "new_string": "hacked"
                }),
                AgentSignal::new(),
                None,
            )
            .await;

        assert!(matches!(result, Err(ToolError::SandboxDenied(_))));
    }
}
