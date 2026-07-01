<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import Toolbar from "$lib/components/Toolbar.svelte";
  import MarkdownPreview from "$lib/components/MarkdownPreview.svelte";
  import { onFileChanged } from "$lib/tauri/events";
  import { reloadCurrentFile } from "$lib/actions/document-actions";

  let unlisten: (() => void) | undefined;

  onMount(async () => {
    unlisten = await onFileChanged((path) => reloadCurrentFile(path));
  });

  onDestroy(() => {
    unlisten?.();
  });
</script>

<main>
  <Toolbar />
  <MarkdownPreview />
</main>

<style>
  main {
    display: flex;
    flex-direction: column;
    height: 100vh;
    overflow: hidden;
  }
</style>
