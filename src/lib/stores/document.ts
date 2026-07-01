import { derived } from "svelte/store";
import { tabStore } from "./tabs";
import type { DocumentState } from "./types";

const empty: DocumentState = {
  filePath: null, fileName: null, content: "", renderedHtml: "",
  frontmatter: null, wordCount: 0, loading: false, error: null,
};

export const document = derived(tabStore, ($tabs) => {
  const found = $tabs.tabs.find((t) => t.filePath === $tabs.activeTabId);
  if (found) return found;
  if ($tabs.pending && $tabs.pending.filePath === $tabs.activeTabId) {
    return {
      ...empty,
      filePath: $tabs.pending.filePath,
      fileName: $tabs.pending.fileName,
      loading: $tabs.pending.error === null,
      error: $tabs.pending.error,
    };
  }
  return empty;
});
