<script lang="ts">
  import { document } from "$lib/stores/document";
  import { openFileDialog } from "$lib/actions/document-actions";
</script>

<header class="toolbar">
  <button onclick={() => openFileDialog()}>打开文件</button>
  {#if $document.fileName}
    <span class="file-info">
      <span class="file-name">{$document.fileName}</span>
      <span class="word-count">{$document.wordCount} 字</span>
    </span>
  {/if}
</header>

<style>
  .toolbar {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 8px 16px;
    border-bottom: 1px solid #e0e0e0;
    background: #fafafa;
    min-height: 40px;
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
  .file-info {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 14px;
    color: #555;
  }
  .file-name {
    font-weight: 500;
  }
  .word-count {
    color: #888;
  }
  @media (prefers-color-scheme: dark) {
    .toolbar {
      border-bottom-color: #444;
      background: #2a2a2a;
    }
    button {
      border-color: #555;
      background: #333;
      color: #eee;
    }
    button:hover {
      border-color: #888;
    }
    .file-info {
      color: #ccc;
    }
    .word-count {
      color: #999;
    }
  }
</style>
