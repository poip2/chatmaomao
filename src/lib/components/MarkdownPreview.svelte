<script lang="ts">
  import { document } from "$lib/stores/document";
  import { openFileDialog } from "$lib/actions/document-actions";
  import { reloadCurrentFile } from "$lib/actions/document-actions";
</script>

<div class="preview">
  {#if $document.loading}
    <div class="status">
      <p>加载中…</p>
    </div>
  {:else if $document.error}
    <div class="status error">
      <p class="error-text">{$document.error}</p>
      {#if $document.filePath}
        <button onclick={() => reloadCurrentFile($document.filePath!)}>重试</button>
      {/if}
    </div>
  {:else if $document.filePath === null}
    <div class="status empty">
      <p>还没有打开文件</p>
      <button onclick={() => openFileDialog()}>打开文件</button>
    </div>
  {:else}
    <div class="markdown-body">
      {@html $document.renderedHtml}
    </div>
  {/if}
</div>

<style>
  .preview {
    flex: 1;
    overflow: auto;
    padding: 24px 32px;
  }
  .status {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100%;
    gap: 12px;
    color: #888;
  }
  .error-text {
    color: #c00;
    font-family: monospace;
    white-space: pre-wrap;
    max-width: 600px;
  }
  button {
    padding: 4px 12px;
    border: 1px solid #ccc;
    border-radius: 4px;
    background: #fff;
    cursor: pointer;
    font-size: 14px;
  }
  button:hover {
    border-color: #999;
  }
  .markdown-body {
    max-width: 800px;
    margin: 0 auto;
    line-height: 1.7;
    font-size: 15px;
  }
  .markdown-body :global(h1),
  .markdown-body :global(h2),
  .markdown-body :global(h3) {
    margin-top: 1.2em;
    margin-bottom: 0.5em;
  }
  .markdown-body :global(pre) {
    background: #f5f5f5;
    padding: 12px;
    border-radius: 4px;
    overflow-x: auto;
  }
  .markdown-body :global(code) {
    font-family: monospace;
    font-size: 0.9em;
  }
  .markdown-body :global(p) {
    margin: 0.6em 0;
  }
  .markdown-body :global(blockquote) {
    border-left: 3px solid #ddd;
    padding-left: 12px;
    color: #666;
    margin: 0.6em 0;
  }
  .markdown-body :global(img) {
    max-width: 100%;
  }
  .markdown-body :global(ul),
  .markdown-body :global(ol) {
    padding-left: 1.5em;
  }
  .markdown-body :global(table) {
    border-collapse: collapse;
  }
  .markdown-body :global(th),
  .markdown-body :global(td) {
    border: 1px solid #ddd;
    padding: 6px 10px;
  }
  @media (prefers-color-scheme: dark) {
    .status {
      color: #999;
    }
    .error-text {
      color: #f66;
    }
    button {
      border-color: #555;
      background: #333;
      color: #eee;
    }
    button:hover {
      border-color: #888;
    }
    .markdown-body :global(pre) {
      background: #1e1e1e;
    }
    .markdown-body :global(blockquote) {
      border-left-color: #555;
      color: #aaa;
    }
    .markdown-body :global(th),
    .markdown-body :global(td) {
      border-color: #555;
    }
  }
</style>
