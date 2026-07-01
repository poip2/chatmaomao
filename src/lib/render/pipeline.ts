import MarkdownIt from "markdown-it";
import DOMPurify from "dompurify";
import taskLists from "markdown-it-task-lists";
import anchor from "markdown-it-anchor";
import texmath from "markdown-it-texmath";
import katex from "katex";
import hljs from "highlight.js/lib/core";
import yamlLib from "js-yaml";


// Register common languages
import javascript from "highlight.js/lib/languages/javascript";
import typescript from "highlight.js/lib/languages/typescript";
import python from "highlight.js/lib/languages/python";
import rust from "highlight.js/lib/languages/rust";
import go from "highlight.js/lib/languages/go";
import bash from "highlight.js/lib/languages/bash";
import json from "highlight.js/lib/languages/json";
import yaml from "highlight.js/lib/languages/yaml";
import xml from "highlight.js/lib/languages/xml";
import css from "highlight.js/lib/languages/css";
import sql from "highlight.js/lib/languages/sql";
import markdown from "highlight.js/lib/languages/markdown";
import java from "highlight.js/lib/languages/java";
import c from "highlight.js/lib/languages/c";
import cpp from "highlight.js/lib/languages/cpp";
import shell from "highlight.js/lib/languages/shell";
import diff from "highlight.js/lib/languages/diff";
import dockerfile from "highlight.js/lib/languages/dockerfile";
import ini from "highlight.js/lib/languages/ini";
import swift from "highlight.js/lib/languages/swift";
import kotlin from "highlight.js/lib/languages/kotlin";
import ruby from "highlight.js/lib/languages/ruby";
import php from "highlight.js/lib/languages/php";

hljs.registerLanguage("javascript", javascript);
hljs.registerLanguage("typescript", typescript);
hljs.registerLanguage("python", python);
hljs.registerLanguage("rust", rust);
hljs.registerLanguage("go", go);
hljs.registerLanguage("bash", bash);
hljs.registerLanguage("json", json);
hljs.registerLanguage("yaml", yaml);
hljs.registerLanguage("xml", xml);
hljs.registerLanguage("html", xml);
hljs.registerLanguage("css", css);
hljs.registerLanguage("sql", sql);
hljs.registerLanguage("markdown", markdown);
hljs.registerLanguage("java", java);
hljs.registerLanguage("c", c);
hljs.registerLanguage("cpp", cpp);
hljs.registerLanguage("shell", shell);
hljs.registerLanguage("diff", diff);
hljs.registerLanguage("dockerfile", dockerfile);
hljs.registerLanguage("toml", ini);
hljs.registerLanguage("ini", ini);
hljs.registerLanguage("swift", swift);
hljs.registerLanguage("kotlin", kotlin);
hljs.registerLanguage("ruby", ruby);
hljs.registerLanguage("php", php);
hljs.registerLanguage("jsx", javascript);
hljs.registerLanguage("tsx", typescript);

export interface RenderResult {
  html: string;
  frontmatter: Record<string, unknown> | null;
  wordCount: number;
}

let md: MarkdownIt | null = null;
let initialized = false;

/**
 * Stamp top-level block elements with `data-source-line="N"` (0-indexed line in
 * source markdown). Used by the scroll-sync logic to map view ↔ raw ↔ editor.
 */
function addSourceLinePlugin(mdInstance: MarkdownIt) {
  mdInstance.core.ruler.push("source-line", (state) => {
    for (const token of state.tokens) {
      if (token.map && token.level === 0 && token.type.endsWith("_open")) {
        token.attrSet("data-source-line", String(token.map[0]));
      }
    }
  });
}

function createMarkdownIt(): MarkdownIt {
  const mdInstance = new MarkdownIt({
    html: false,
    linkify: true,
    typographer: true,
    highlight: (str, lang) => {
      if (lang && lang !== "mermaid" && hljs.getLanguage(lang)) {
        try {
          return hljs.highlight(str, { language: lang }).value;
        } catch {}
      }
      try {
        return hljs.highlightAuto(str).value;
      } catch {}
      return "";
    },
  });

  mdInstance.use(texmath, {
    engine: katex,
    delimiters: "dollars",
  });

  mdInstance.use(taskLists, { enabled: false, label: true });
  mdInstance.use(anchor, {
    permalink: false,
    slugify: (s: string) =>
      s
        .toLowerCase()
        .trim()
        .replace(/[^\w\s-]/g, "")
        .replace(/\s+/g, "-"),
  });
  addSourceLinePlugin(mdInstance);

  return mdInstance;
}

export async function initRenderer(): Promise<void> {
  if (initialized) return;

  md = createMarkdownIt();

  initialized = true;
}

export function render(markdown: string, baseDir?: string, resolveImageSrc?: (absPath: string) => string): string {
  return renderFull(markdown, baseDir, resolveImageSrc).html;
}

export function renderFull(markdown: string, baseDir?: string, resolveImageSrc?: (absPath: string) => string): RenderResult {
  if (!md) {
    // Auto-init synchronously if not yet initialized
    md = createMarkdownIt();
    initialized = true;
  }

  // Extract frontmatter
  let content = markdown;
  let frontmatter: Record<string, unknown> | null = null;
  const fmMatch = markdown.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n([\s\S]*)$/);
  if (fmMatch) {
    try {
      const parsed = yamlLib.load(fmMatch[1]);
      // Ensure parsed result is a plain object (not array, string, number, etc.)
      if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
        frontmatter = parsed as Record<string, unknown>;
        content = fmMatch[2];
      }
    } catch (err) {
      console.warn("Failed to parse frontmatter:", err);
      // Not valid frontmatter, treat as regular content
    }
  }

  // Word count with CJK support
  const wordCount = countWords(content);

  const raw = md.render(content);
  let html = DOMPurify.sanitize(raw, {
    ADD_TAGS: [
      "pre",
      "code",
      "math",
      "mrow",
      "mi",
      "mo",
      "mn",
      "msup",
      "msub",
      "mfrac",
      "mover",
      "munder",
      "msqrt",
      "mtable",
      "mtr",
      "mtd",
      "annotation",
      "semantics",
      "mspace",
      "mtext",
      "mpadded",
      "svg",
      "path",
      "line",
      "rect",
      "circle",
      "g",
      "text",
      "defs",
      "marker",
      "polygon",
      "polyline",
      "foreignObject",
    ],
    ADD_ATTR: [
      "class",
      "style",
      "xmlns",
      "viewBox",
      "d",
      "fill",
      "stroke",
      "stroke-width",
      "transform",
      "x",
      "y",
      "width",
      "height",
      "text-anchor",
      "dominant-baseline",
      "font-size",
      "font-family",
      "marker-end",
      "id",
      "aria-hidden",
      "focusable",
      "role",
      "mathvariant",
      "encoding",
    ],
  });

  if (baseDir) {
    html = resolveRelativeImages(html, baseDir, resolveImageSrc);
  }

  return { html, frontmatter, wordCount };
}

/**
 * Count words in text with CJK support.
 * CJK characters are counted individually, non-CJK parts are split by whitespace.
 */
function countWords(text: string): number {
  // CJK Unified Ideographs: U+4E00 to U+9FFF (汉字)
  // CJK Extension A: U+3400 to U+4DBF (扩展A区汉字)
  // CJK Compatibility Ideographs: U+F900 to U+FAFF (兼容汉字)
  // CJK Radicals Supplement: U+2E80 to U+2EFF (部首补充)
  // Kangxi Radicals: U+2F00 to U+2FDF (康熙部首)
  // Hiragana: U+3040 to U+309F (平假名)
  // Katakana: U+30A0 to U+30FF (片假名)
  // Hangul Jamo: U+1100 to U+11FF (韩文字母)
  // Hangul Compatibility Jamo: U+3130 to U+318F (韩文兼容字母)
  // Hangul Syllables: U+AC00 to U+D7AF (韩文音节)
  // 注意：排除了 CJK Symbols and Punctuation (U+3000-U+303F) 以避免计数标点符号
  const cjkRegex = /[\u{4E00}-\u{9FFF}\u{3400}-\u{4DBF}\u{F900}-\u{FAFF}\u{2E80}-\u{2EFF}\u{2F00}-\u{2FDF}\u{3040}-\u{309F}\u{30A0}-\u{30FF}\u{1100}-\u{11FF}\u{3130}-\u{318F}\u{AC00}-\u{D7AF}]/gu;
  
  // Count CJK characters
  const cjkMatches = text.match(cjkRegex);
  const cjkCount = cjkMatches ? cjkMatches.length : 0;
  
  // Replace CJK characters with spaces, then count non-CJK words
  const nonCjkText = text.replace(cjkRegex, ' ');
  const nonCjkWords = nonCjkText.trim().split(/\s+/).filter(Boolean);
  const nonCjkCount = nonCjkWords.length;
  
  return cjkCount + nonCjkCount;
}

function resolveRelativeImages(html: string, baseDir: string, resolveImageSrc?: (absPath: string) => string): string {
  const resolve = resolveImageSrc ?? ((p: string) => p);
  return html.replace(
    /(<img\s[^>]*?\bsrc=")(?!https?:\/\/|data:|blob:)([^"]+)(")/gi,
    (_match, before, src, after) => {
      const absPath = `${baseDir}/${src}`.replace(/\/\.\//g, "/");
      try {
        return `${before}${resolve(absPath)}${after}`;
      } catch {
        return `${before}${src}${after}`;
      }
    },
  );
}

export function isInitialized(): boolean {
  return initialized;
}
