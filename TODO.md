# TODO

## 安全相关 (Security)

### Sandbox known limitations
**状态**: 已识别，记录在源码 doc comments 中
**描述**: 各平台沙箱实现均有已知的安全边界限制：
- **macOS seatbelt**: SBPL 使用 `(allow default)` 默认允许全局文件读取（仅通过 protected_paths + writable_roots 限定边界），不像 Linux bwrap 那样做选择性 `/etc` bind-mount。系统文件如 `/etc/passwd` 在 writable_roots 外但不能被读取限制覆盖——这是后续加固里程碑。参见 `src-tauri/src/agent/sandbox/seatbelt.rs` "Known limitation: global read isolation"。
- **Linux Landlock fallback**: 网络隔离需要 ABI v4 (Linux 6.7+)，在旧内核上静默退化。bwrap 模式无此限制。
- **Windows read isolation**: `best-effort`——ACL 设置失败不会阻塞沙箱启动。
- **ProxyOnly**: 仅在 macOS seatbelt 实现，Linux/Windows 显式报错而非静默降级。
**相关**: sandbox module doc comments

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
