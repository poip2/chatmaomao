import { writable } from "svelte/store";

export interface RecentFile { path: string; fileName: string; openedAt: number }

export const recents = writable<RecentFile[]>([]);

export function addRecentFile(path: string, fileName: string) {
  recents.update((list) => [{ path, fileName, openedAt: Date.now() }, ...list.filter((f) => f.path !== path)].slice(0, 10));
}
