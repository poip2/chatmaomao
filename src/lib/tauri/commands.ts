import { invoke } from "@tauri-apps/api/core";

export function readMarkdownFile(path: string): Promise<string> {
  return invoke<string>("read_markdown_file", { path });
}

export function writeMarkdownFile(path: string, content: string): Promise<void> {
  return invoke("write_markdown_file", { path, content });
}

export function startWatching(path: string): Promise<void> {
  return invoke("start_watching", { path });
}

export function stopWatching(path: string): Promise<void> {
  return invoke("stop_watching", { path });
}
