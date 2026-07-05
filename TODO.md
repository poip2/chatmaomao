# TODO

## 安全相关 (Security)

### Sandbox known limitations
**状态**: 已识别，记录在源码 doc comments 中
**描述**: 各平台沙箱实现均有已知的安全边界限制：
- **macOS seatbelt**: SBPL 使用 `(allow default)` 默认允许全局文件读取（仅通过 protected_paths + writable_roots 限定边界），不像 Linux bwrap 那样做选择性 `/etc` bind-mount。系统文件如 `/etc/passwd` 在 writable_roots 外但不能被读取限制覆盖——这是后续加固里程碑。参见 `src-tauri/src/agent/sandbox/seatbelt.rs` "Known limitation: global read isolation"。
- **Linux Landlock fallback**: 网络隔离需要 ABI v4 (Linux 6.7+)，在旧内核上静默退化。bwrap 模式无此限制。
- **Windows read isolation**: `best-effort`——ACL 设置失败不会阻塞沙箱启动。
- **Windows Job Object**: 如果子进程已在外层 Job Object 中（如 CI runner），`AssignProcessToJobObject` 会失败，沙箱优雅降级为仅 Low IL + ACL 隔离——失去资源限制和 kill-on-close。
- **ProxyOnly**: 仅在 macOS seatbelt 实现，Linux/Windows 显式报错而非静默降级。
**相关**: sandbox module doc comments

### Tech debt: duplicate helper functions
**状态**: 已记录，待所有沙箱测试通过后合并
**描述**: 多个模块中存在功能重复的辅助函数：
- **`canonicalize_best_effort`**: 有三份独立实现——`tools/mod.rs`（返回 `Result<PathBuf, ToolError>`）、`sandbox/linux.rs`（返回 `(PathBuf, Option<OsString>)`）、`sandbox/seatbelt.rs`（命名为 `canonicalize_best_effort_macos`，返回 `(PathBuf, Option<OsString>)`）。三者的语义略有不同（tools 版对 containment 更严格），需在所有沙箱测试通过后做一致性检查，但暂不合并。
- **PipeChunk / drain_channels / spawn_pipe_reader / kill_process_tree**: `sandbox/mod.rs` 与 `tools/bash.rs` 中有重复的进程生命周期辅助代码。当前保持分离以避免循环依赖（bash.rs 不依赖 sandbox），后续可考虑提取到共享模块。
**相关**: no-mistakes 审查发现 F04, F05

### F1 - 路径校验增强
**状态**: 第一档（后缀白名单）已完成，agent tools 已完成全面校验，commands 仍待修复
**文件**: `src-tauri/src/commands/file.rs`（待修复）, `src-tauri/src/agent/tools/mod.rs`（已完成）
**描述**: agent 工具（read/write/edit）已实现完整的路径校验：`validate_path()` 通过 `canonicalize()` 解析符号链接和 `..`，执行 workspace 收容检查和 protected path 检查（如 `.git`、`.agents`）。但 Tauri commands（`read_markdown_file`/`write_markdown_file`）仍只校验后缀白名单，不能防止"凑巧后缀对的敏感文件"的边缘情况。
**待办**: 分发前需为 commands 加"仅信任已打开路径"的校验。做法是后端维护一份"当前允许操作的路径集合"（`Mutex<HashSet<String>>`），新增 `mark_path_open(path)`/`mark_path_closed(path)` 两个命令，前端 `document-actions.ts` 的 `openFile` 成功后调 `mark_path_open`、`closeFile` 时调 `mark_path_closed`。
**相关**: no-mistakes 审查发现 F1

### F7 - CSP 配置
**状态**: 延后到分发前处理
**文件**: `src-tauri/tauri.conf.json`
**描述**: CSP 设置为 `null` 禁用了所有内容安全策略。考虑到 DOMPurify 清理和 KaTeX 需求，这是可以接受的，但移除了一个深度防御层。
**待办**: 分发前配置 CSP，与 F1 一起处理（CSP 收紧能降低 F1 那种攻击路径的可行性，两个放一起处理更划算）。
**相关**: no-mistakes 审查发现 F7
