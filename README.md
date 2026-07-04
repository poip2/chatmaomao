# MaoMaoChat

A Tauri + Rust + Svelte markdown notes app with an AI agent backend.

## Architecture

```
Frontend (Svelte)   ←→   Tauri commands (Rust)   ←→   AI Agent Backend
                                                         ├── types        (core data model)
                                                         └── tools        (agent tool implementations)
                                                              ├── read     (file reader)
                                                              ├── write    (file writer)
                                                              ├── edit     (exact-string replace)
                                                              └── bash     (shell executor)
```

### Agent backend (`src-tauri/src/agent/`)

- **`types.rs`** — Core type definitions: `AgentTool`, `ToolDefinition`, `AgentSignal`,
  `SandboxPolicy`, `ToolError`, `AgentLoopConfig`, and supporting types.
- **`tools/`** — Implementations of the agent tools that the LLM can call:
  - `read` — Reads file contents with path containment and protected-path checks.
  - `write` — Creates/overwrites files, creating parent directories as needed.
  - `edit` — Performs exact-string replacement in a file (must appear exactly once).
  - `bash` — Executes shell commands via a pluggable `ProcessExecutor` trait with
    concurrent stdout/stderr, timeout, cancellation, process-tree kill, stream
    callback throttling, and output truncation.
- **Shared path validation** (`tools/mod.rs`) — `validate_path()` enforces
  workspace containment and protected-path checks for read/write/edit tools.

## Recommended IDE Setup

[VS Code](https://code.visualstudio.com/) + [Svelte](https://marketplace.visualstudio.com/items?itemName=svelte.svelte-vscode) + [Tauri](https://marketplace.visualstudio.com/items?itemName=tauri-apps.tauri-vscode) + [rust-analyzer](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer).
