import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export function onFileChanged(callback: (path: string) => void): Promise<UnlistenFn> {
  return listen<string>("file-changed", (event) => callback(event.payload));
}
