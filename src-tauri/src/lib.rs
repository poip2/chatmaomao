mod commands;

use commands::watcher::WatcherState;

#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(WatcherState::new())
        .invoke_handler(tauri::generate_handler![
            greet,
            commands::file::read_markdown_file,
            commands::file::write_markdown_file,
            commands::watcher::start_watching,
            commands::watcher::stop_watching
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
