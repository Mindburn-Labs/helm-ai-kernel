import celGrammar from "../grammars/cel.tmLanguage.json";
import { createHighlighterCore } from "shiki/core";
import { createJavaScriptRegexEngine } from "shiki/engine/javascript";
import darkPlus from "shiki/themes/dark-plus.mjs";
import lightPlus from "shiki/themes/light-plus.mjs";

/**
 * Lazy Shiki singleton for CEL highlighting.
 *
 * Why lazy: Shiki still has a meaningful parser/theme cost. We only pay that
 * cost the first time `<CodeBlock language="cel">` mounts. Consumers that
 * never see CEL never download the highlighter chunk.
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
      return createHighlighterCore({
        themes: [darkPlus, lightPlus],
        langs: [celGrammar],
        engine: createJavaScriptRegexEngine(),
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
