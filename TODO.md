# TODO

## 安全相关 (Security)

### F1 - 路径校验增强
**状态**: 第一档（后缀白名单）已完成，第二档延后
**文件**: `src-tauri/src/commands/file.rs`
**描述**: 当前只校验文件后缀，不能防止"凑巧后缀对的敏感文件"的边缘情况。
**待办**: 分发前需加"仅信任已打开路径"的校验。做法是后端维护一份"当前允许操作的路径集合"（`Mutex<HashSet<String>>`），新增 `mark_path_open(path)`/`mark_path_closed(path)` 两个命令，前端 `document-actions.ts` 的 `openFile` 成功后调 `mark_path_open`、`closeFile` 时调 `mark_path_closed`。
**相关**: no-mistakes 审查发现 F1

### F7 - CSP 配置
**状态**: 延后到分发前处理
**文件**: `src-tauri/tauri.conf.json`
**描述**: CSP 设置为 `null` 禁用了所有内容安全策略。考虑到 DOMPurify 清理和 KaTeX 需求，这是可以接受的，但移除了一个深度防御层。
**待办**: 分发前配置 CSP，与 F1 一起处理（CSP 收紧能降低 F1 那种攻击路径的可行性，两个放一起处理更划算）。
**相关**: no-mistakes 审查发现 F7
