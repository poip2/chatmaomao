use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use notify::{EventHandler, RecommendedWatcher, RecursiveMode, Watcher};
use tauri::{AppHandle, Emitter};

/// State that holds active file watchers keyed by path.
pub struct WatcherState {
    watchers: Mutex<HashMap<String, RecommendedWatcher>>,
}

impl WatcherState {
    pub fn new() -> Self {
        Self {
            watchers: Mutex::new(HashMap::new()),
        }
    }
}

/// An event handler that emits a Tauri "file-changed" event when a file change is detected.
struct FileChangeHandler {
    app: AppHandle,
    path: String,
}

impl EventHandler for FileChangeHandler {
    fn handle_event(&mut self, event: Result<notify::Event, notify::Error>) {
        if let Ok(ev) = event {
            // Only emit for modify and create events (not remove/rename/etc.)
            if matches!(
                ev.kind,
                notify::EventKind::Modify(_) | notify::EventKind::Create(_)
            ) {
                let _ = self.app.emit("file-changed", &self.path);
            }
        }
    }
}

#[tauri::command]
pub fn start_watching(
    app: AppHandle,
    state: tauri::State<'_, WatcherState>,
    path: String,
) -> Result<(), String> {
    let mut watchers = state.watchers.lock().map_err(|e| e.to_string())?;

    // Don't re-watch if already watching
    if watchers.contains_key(&path) {
        return Ok(());
    }

    let handler = FileChangeHandler {
        app,
        path: path.clone(),
    };
    let mut watcher = notify::recommended_watcher(handler)
        .map_err(|e| format!("Failed to create watcher: {}", e))?;

    watcher
        .watch(Path::new(&path), RecursiveMode::NonRecursive)
        .map_err(|e| format!("Failed to watch {}: {}", path, e))?;

    watchers.insert(path, watcher);
    Ok(())
}

#[tauri::command]
pub fn stop_watching(state: tauri::State<'_, WatcherState>, path: String) -> Result<(), String> {
    let mut watchers = state.watchers.lock().map_err(|e| e.to_string())?;
    // Removing and dropping the watcher stops watching
    watchers.remove(&path);
    Ok(())
}
