import { writable } from "svelte/store";
import type { DocumentState } from "./types";

interface TabsState {
  tabs: DocumentState[];
  activeTabId: string | null; // 用 filePath 当 id
  pending: { filePath: string; fileName: string; error: string | null } | null;
}

function createTabStore() {
  const { subscribe, update } = writable<TabsState>({ tabs: [], activeTabId: null, pending: null });
  return {
    subscribe,
    startOpening(filePath: string, fileName: string) {
      update((s) => ({ ...s, activeTabId: filePath, pending: { filePath, fileName, error: null } }));
    },
    failOpening(filePath: string, fileName: string, message: string) {
      update((s) => {
        if (s.pending && s.pending.filePath === filePath) {
          return { ...s, pending: { ...s.pending, error: message } };
        }
        return s;
      });
    },
    addTab(filePath: string, fileName: string, content: string, renderedHtml: string, frontmatter: Record<string, unknown> | null, wordCount: number) {
      update((s) => {
        const tab: DocumentState = { filePath, fileName, content, renderedHtml, frontmatter, wordCount, loading: false, error: null };
        const exists = s.tabs.some((t) => t.filePath === filePath);
        const tabs = exists ? s.tabs.map((t) => (t.filePath === filePath ? tab : t)) : [...s.tabs, tab];
        return { tabs, activeTabId: filePath, pending: null };
      });
    },
    updateTabContent(filePath: string, content: string, renderedHtml: string, frontmatter: Record<string, unknown> | null, wordCount: number) {
      update((s) => ({
        ...s,
        tabs: s.tabs.map((t) => (t.filePath === filePath ? { ...t, content, renderedHtml, frontmatter, wordCount } : t)),
      }));
    },
    closeTab(filePath: string) {
      update((s) => {
        const tabs = s.tabs.filter((t) => t.filePath !== filePath);
        const activeTabId = s.activeTabId === filePath ? (tabs[0]?.filePath ?? null) : s.activeTabId;
        const pending = s.pending?.filePath === filePath ? null : s.pending;
        return { tabs, activeTabId, pending };
      });
    },
  };
}

export const tabStore = createTabStore();
