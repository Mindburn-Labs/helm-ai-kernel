import celGrammar from "../grammars/cel.tmLanguage.json";

/**
 * Lazy Shiki singleton for CEL highlighting.
 *
 * Why lazy: Shiki's wasm + grammars cost ~80kb gzip. We only pay that cost
 * the first time `<CodeBlock language="cel">` mounts. Consumers that never
 * see CEL never download the highlighter chunk.
 *
 * Why a singleton: each `getHighlighter()` call instantiates a Shiki engine.
 * Reusing one across all CodeBlocks keeps memory + repeat-mount cost low.
 */

interface HighlighterInstance {
  codeToHtml: (code: string, options: { lang: string; theme: string }) => string;
}

let highlighterPromise: Promise<HighlighterInstance> | null = null;

/**
 * Returns the singleton Shiki highlighter, lazy-loading on first call.
 */
export function getHighlighter(): Promise<HighlighterInstance> {
  if (!highlighterPromise) {
    highlighterPromise = (async () => {
      const shiki = (await import("shiki")) as unknown as {
        getHighlighter?: (opts: { themes: string[]; langs: unknown[] }) => Promise<HighlighterInstance>;
        createHighlighter?: (opts: { themes: string[]; langs: unknown[] }) => Promise<HighlighterInstance>;
      };
      const factory = shiki.getHighlighter ?? shiki.createHighlighter;
      if (!factory) {
        throw new Error("Shiki: neither getHighlighter nor createHighlighter exported.");
      }
      return factory({
        themes: ["dark-plus", "light-plus"],
        langs: [celGrammar],
      });
    })();
  }
  return highlighterPromise;
}

/**
 * Highlight a CEL expression to HTML. Returns sanitized markup safe for
 * `dangerouslySetInnerHTML` (Shiki escapes user input).
 *
 * Errors fall back to plain `<pre><code>` text so a CEL highlight glitch
 * never blocks rendering.
 */
export async function highlightCel(code: string, theme: "dark" | "light" = "dark"): Promise<string> {
  try {
    const highlighter = await getHighlighter();
    return highlighter.codeToHtml(code, { lang: "cel", theme: theme === "dark" ? "dark-plus" : "light-plus" });
  } catch (error) {
    console.warn("[HELM highlighter] falling back to plain text:", error);
    const escaped = code
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
    return `<pre><code>${escaped}</code></pre>`;
  }
}

/**
 * Test seam — reset the singleton so a unit test can mock the dynamic import.
 */
export function _resetHighlighterForTests(): void {
  highlighterPromise = null;
}
