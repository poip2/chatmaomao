# MaoMaoChat

A Tauri + Rust + Svelte markdown notes app with an AI agent backend.

## Architecture

```
Frontend (Svelte)   ←→   Tauri commands (Rust)   ←→   AI Agent Backend
                                                         ├── types        (core data model)
                                                         ├── tools        (agent tool implementations)
                                                         │    ├── read     (file reader)
                                                         │    ├── write    (file writer)
                                                         │    ├── edit     (exact-string replace)
                                                         │    └── bash     (sandboxed shell executor)
                                                         └── sandbox      (platform-specific sandbox backends)
                                                              ├── linux    (bwrap + landlock)
                                                              ├── windows  (job object + low-IL token + ACL read isolation)
                                                              └── seatbelt (macOS sandbox-exec)
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
- **`sandbox/`** — Cross-platform sandbox executor for bash commands:
  - `mod.rs` — `SandboxExecutor` implementing `ProcessExecutor`, delegates to
    platform backends, plus black-box sandbox penetration tests.
  - `linux.rs` — bwrap (bubblewrap) with Landlock fallback, mount-level
    protected-path masking, selective `/etc` bind-mounts for read isolation.
  - `windows.rs` — Job Object resource limits + Low-Integrity restricted token +
    ACL deny-read on `%USERPROFILE%` with explicit allow-read on workspace.
  - `seatbelt.rs` — macOS `sandbox-exec` with dynamically generated SBPL,
    including `ProxyOnly` network policy.
- **Shared path validation** (`tools/mod.rs`) — `validate_path()` enforces
  workspace containment and protected-path checks for read/write/edit tools.

## Recommended IDE Setup

[VS Code](https://code.visualstudio.com/) + [Svelte](https://marketplace.visualstudio.com/items?itemName=svelte.svelte-vscode) + [Tauri](https://marketplace.visualstudio.com/items?itemName=tauri-apps.tauri-vscode) + [rust-analyzer](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer).
