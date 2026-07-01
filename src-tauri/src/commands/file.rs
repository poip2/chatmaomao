// TODO(security): 分发前需加“仅信任已打开路径”的校验，见 F1

const ALLOWED_EXTENSIONS: &[&str] = &["md", "markdown", "mdown", "mkd", "txt"];

fn is_allowed_path(path: &str) -> bool {
    std::path::Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ALLOWED_EXTENSIONS.contains(&ext.to_lowercase().as_str()))
        .unwrap_or(false)
}

#[tauri::command]
pub fn read_markdown_file(path: String) -> Result<String, String> {
    if !is_allowed_path(&path) {
        return Err("Only markdown/text files can be read".into());
    }
    std::fs::read_to_string(&path).map_err(|e| format!("Failed to read {}: {}", path, e))
}

#[tauri::command]
pub fn write_markdown_file(path: String, content: String) -> Result<(), String> {
    if !is_allowed_path(&path) {
        return Err("Only markdown/text files can be written".into());
    }
    std::fs::write(&path, content).map_err(|e| format!("Failed to write {}: {}", path, e))
}
