import { convertFileSrc } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { getCurrentWindow } from "@tauri-apps/api/window";
import * as commands from "../tauri/commands";
import { renderFull } from "../render/pipeline";
import { tabStore } from "../stores/tabs";
import { addRecentFile } from "../stores/recents";

export async function openFile(path: string): Promise<void> {
  const fileName = path.split("/").pop() ?? path;

  tabStore.startOpening(path, fileName);

  try {
    const content = await commands.readMarkdownFile(path);
    const baseDir = path.includes("/")
      ? path.substring(0, path.lastIndexOf("/"))
      : undefined;
    const result = renderFull(content, baseDir, convertFileSrc);

    tabStore.addTab(
      path,
      fileName,
      content,
      result.html,
      result.frontmatter,
      result.wordCount,
    );

    addRecentFile(path, fileName);
    getCurrentWindow()
      .setTitle(`${fileName} — MaoMaoChat`)
      .catch(() => {});
    commands.startWatching(path).catch(() => {});
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    tabStore.failOpening(path, fileName, message);
    console.error("Failed to open file:", err);
  }
}

export async function openFileDialog(): Promise<void> {
  try {
    const selected = await open({
      multiple: false,
      filters: [
        {
          name: "Markdown",
          extensions: ["md", "markdown", "mdown", "mkd", "txt"],
        },
      ],
    });

    // @tauri-apps/plugin-dialog v2 open() returns string | null for single file selection
    if (typeof selected === "string") {
      await openFile(selected);
    }
    // If selected is null, user cancelled the dialog - do nothing
  } catch (err) {
    console.error("File dialog error:", err);
  }
}

export async function reloadCurrentFile(path: string): Promise<void> {
  try {
    const content = await commands.readMarkdownFile(path);
    const baseDir = path.substring(0, path.lastIndexOf("/"));
    const result = renderFull(content, baseDir, convertFileSrc);

    tabStore.updateTabContent(
      path,
      content,
      result.html,
      result.frontmatter,
      result.wordCount,
    );
  } catch (err) {
    console.error("Failed to reload file:", err);
  }
}

export async function closeFile(path: string): Promise<void> {
  try {
    await commands.stopWatching(path);
  } catch {
    // ignore errors when stopping watcher
  }
  tabStore.closeTab(path);
}
