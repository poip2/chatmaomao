export interface DocumentState {
  filePath: string | null;
  fileName: string | null;
  content: string;
  renderedHtml: string;
  frontmatter: Record<string, unknown> | null;
  wordCount: number;
  loading: boolean;
  error: string | null;
}
