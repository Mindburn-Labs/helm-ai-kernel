"use client";

import { Check, ChevronRight, Copy } from "lucide-react";
import { type KeyboardEvent, type ReactNode, useEffect, useId, useMemo, useRef, useState } from "react";
import { useToast } from "./core";

/* DiffViewer ---------------------------------------------------------- */

export type DiffHunkKind = "context" | "add" | "remove";

export interface DiffHunk {
  readonly kind: DiffHunkKind;
  readonly content: string;
  readonly oldLine?: number;
  readonly newLine?: number;
}

const DIFF_PREFIX: Record<DiffHunkKind, string> = {
  context: " ",
  add: "+",
  remove: "-",
};

export function DiffViewer({
  hunks,
  ariaLabel = "Diff",
}: {
  readonly hunks: readonly DiffHunk[];
  readonly ariaLabel?: string;
}) {
  const captionId = useId();
  return (
    <figure className="diff-viewer" role="group" aria-labelledby={captionId}>
      <figcaption id={captionId} className="sr-only">{ariaLabel}</figcaption>
      <table className="diff-table">
        <thead className="sr-only">
          <tr>
            <th scope="col">Old line</th>
            <th scope="col">New line</th>
            <th scope="col">Change</th>
            <th scope="col">Content</th>
          </tr>
        </thead>
        <tbody>
          {hunks.map((hunk, index) => (
            <tr
              key={`${hunk.kind}-${index}`}
              className={`diff-row diff-row--${hunk.kind}`}
              aria-label={`${hunk.kind} line: ${hunk.content}`}
            >
              <td className="diff-line-num" aria-hidden="true">{hunk.oldLine ?? ""}</td>
              <td className="diff-line-num" aria-hidden="true">{hunk.newLine ?? ""}</td>
              <td className="diff-marker" aria-hidden="true">{DIFF_PREFIX[hunk.kind]}</td>
              <td className="diff-content"><code>{hunk.content}</code></td>
            </tr>
          ))}
        </tbody>
      </table>
    </figure>
  );
}

/* CodeBlock ----------------------------------------------------------- */

export interface CodeBlockProps {
  readonly code: string;
  readonly language?: string;
  readonly showLineNumbers?: boolean;
  readonly ariaLabel?: string;
  readonly lintIssues?: readonly CodeLintFinding[];
  readonly onJumpToLine?: (line: number) => void;
}

export type CodeLintSeverity = "info" | "warn" | "error";

export interface CodeLintFinding {
  readonly severity: CodeLintSeverity;
  readonly line: number;
  readonly column?: number;
  readonly endColumn?: number;
  readonly rule: string;
  readonly message: string;
  readonly fixHint?: string;
}

function extractHighlightedInner(html: string): string {
  // Shiki output: <pre ...><code>...</code></pre>. Strip the wrappers, keep
  // only the inner span tree so it sits inside our existing `.code-content`.
  const match = html.match(/<code[^>]*>([\s\S]*)<\/code>/);
  return match?.[1] ?? html;
}

export function CodeBlock({
  code,
  language,
  showLineNumbers = false,
  ariaLabel,
  lintIssues,
  onJumpToLine,
}: CodeBlockProps) {
  const [copied, setCopied] = useState(false);
  const toast = useToast();
  const captionId = useId();
  const lines = useMemo(() => code.replace(/\n$/, "").split("\n"), [code]);
  const isCel = language === "cel";
  const highlightKey = isCel ? `${language}:${code}` : null;
  const [highlightedCel, setHighlightedCel] = useState<{ readonly key: string; readonly lines: readonly string[] } | null>(null);
  const celHtml = highlightedCel?.key === highlightKey ? highlightedCel.lines : null;
  const lineRefs = useRef<Array<HTMLSpanElement | null>>([]);

  useEffect(() => {
    if (!highlightKey) return undefined;
    let cancelled = false;
    void (async () => {
      try {
        const { highlightCel } = await import("../lib/highlighter");
        const rendered = await Promise.all(lines.map((line) => highlightCel(line || " ")));
        if (cancelled) return;
        setHighlightedCel({ key: highlightKey, lines: rendered.map((html) => extractHighlightedInner(html)) });
      } catch (error) {
        console.warn("[HELM CodeBlock] CEL highlight failed:", error);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [highlightKey, lines]);

  const findingsByLine = useMemo(() => {
    const map = new Map<number, CodeLintFinding[]>();
    if (lintIssues) {
      for (const finding of lintIssues) {
        const list = map.get(finding.line) ?? [];
        list.push(finding);
        map.set(finding.line, list);
      }
    }
    return map;
  }, [lintIssues]);

  const copy = async () => {
    try {
      if (!navigator.clipboard) throw new Error("Clipboard API unavailable in this browser context.");
      await navigator.clipboard.writeText(code);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 900);
    } catch (error) {
      toast.push({
        title: "Could not copy code",
        detail: error instanceof Error ? error.message : "Browser blocked clipboard access.",
        tone: "failed",
      });
    }
  };

  // External jump-to-line: callable via ref-equivalent pattern through the prop.
  // Consumers (e.g. PolicyLintBanner) call `onJumpToLine(line)` themselves;
  // we expose the actual scroll behavior via a stable handler attached to lines.
  const focusLine = (lineNumber: number) => {
    const target = lineRefs.current[lineNumber - 1];
    if (!target) return;
    target.scrollIntoView({ block: "center", behavior: "instant" as ScrollBehavior });
    target.classList.add("code-line--flash");
    window.setTimeout(() => target.classList.remove("code-line--flash"), 1200);
    onJumpToLine?.(lineNumber);
  };

  return (
    <figure className="code-block" aria-labelledby={ariaLabel ? captionId : undefined} data-language={language ?? "plain"}>
      {ariaLabel ? <figcaption id={captionId} className="sr-only">{ariaLabel}</figcaption> : null}
      <header className="code-block-head">
        {language ? <span className="code-block-lang">{language}</span> : <span aria-hidden="true" />}
        <button type="button" className="icon-button" aria-label={copied ? "Code copied" : "Copy code"} onClick={copy}>
          {copied ? <Check size={13} aria-hidden="true" /> : <Copy size={13} aria-hidden="true" />}
        </button>
      </header>
      <pre tabIndex={0} className={showLineNumbers ? "code-block-pre with-lines" : "code-block-pre"}>
        <code>
          {lines.map((line, index) => {
            const lineNo = index + 1;
            const findings = findingsByLine.get(lineNo);
            const severity = findings?.reduce<CodeLintSeverity>(
              (worst, f) => (f.severity === "error" ? "error" : worst === "error" ? "error" : f.severity === "warn" ? "warn" : worst),
              "info",
            );
            const lineClass = `code-line${findings ? ` code-line--lint code-line--lint-${severity}` : ""}`;
            const ariaDesc = findings?.map((f) => `${f.severity}: ${f.message}`).join(" ");
            return (
              <span
                key={index}
                ref={(node) => { lineRefs.current[index] = node; }}
                className={lineClass}
                data-line={lineNo}
                aria-description={ariaDesc}
                onDoubleClick={onJumpToLine ? () => focusLine(lineNo) : undefined}
              >
                {showLineNumbers ? <span className="code-gutter" aria-hidden="true">{lineNo}</span> : null}
                {isCel && celHtml?.[index] !== undefined ? (
                  <span className="code-content code-content--highlighted" dangerouslySetInnerHTML={{ __html: celHtml[index] ?? "" }} />
                ) : (
                  <span className="code-content">{line || " "}</span>
                )}
              </span>
            );
          })}
        </code>
      </pre>
    </figure>
  );
}

/* Tree ---------------------------------------------------------------- */

export interface TreeNode {
  readonly id: string;
  readonly label: ReactNode;
  readonly icon?: ReactNode;
  readonly rail?: string;
  readonly defaultExpanded?: boolean;
  readonly children?: readonly TreeNode[];
}

export interface TreeRowContext {
  readonly level: number;
  readonly hasChildren: boolean;
  readonly isSelected: boolean;
  readonly isExpanded: boolean | undefined;
  readonly index: number;
}

export interface TreeProps {
  readonly nodes: readonly TreeNode[];
  readonly selectedId?: string;
  readonly onSelect?: (id: string) => void;
  readonly ariaLabel: string;
  readonly renderRow?: (node: TreeNode, ctx: TreeRowContext) => ReactNode;
}

interface FlatNode {
  readonly node: TreeNode;
  readonly level: number;
  readonly hasChildren: boolean;
}

function flattenVisible(
  nodes: readonly TreeNode[],
  expanded: ReadonlySet<string>,
  level = 1,
  into: FlatNode[] = [],
): FlatNode[] {
  for (const node of nodes) {
    const hasChildren = (node.children?.length ?? 0) > 0;
    into.push({ node, level, hasChildren });
    if (hasChildren && expanded.has(node.id) && node.children) {
      flattenVisible(node.children, expanded, level + 1, into);
    }
  }
  return into;
}

export function Tree({ nodes, selectedId, onSelect, ariaLabel, renderRow }: TreeProps) {
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(() => {
    const initial = new Set<string>();
    const walk = (list: readonly TreeNode[]) => {
      for (const node of list) {
        if (node.defaultExpanded && node.children?.length) initial.add(node.id);
        if (node.children?.length) walk(node.children);
      }
    };
    walk(nodes);
    return initial;
  });
  const visible = useMemo(() => flattenVisible(nodes, expanded), [nodes, expanded]);
  const itemRefs = useRef<Array<HTMLButtonElement | null>>([]);
  const activeIndex = Math.max(0, visible.findIndex((entry) => entry.node.id === selectedId));

  const toggle = (id: string) => {
    setExpanded((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const focusRow = (index: number) => {
    const button = itemRefs.current[index];
    button?.focus();
  };

  const onKeyDown = (event: KeyboardEvent<HTMLButtonElement>, currentIndex: number, entry: FlatNode) => {
    const last = visible.length - 1;
    if (event.key === "ArrowDown") {
      event.preventDefault();
      focusRow(Math.min(last, currentIndex + 1));
      return;
    }
    if (event.key === "ArrowUp") {
      event.preventDefault();
      focusRow(Math.max(0, currentIndex - 1));
      return;
    }
    if (event.key === "ArrowRight") {
      event.preventDefault();
      if (entry.hasChildren && !expanded.has(entry.node.id)) toggle(entry.node.id);
      else if (entry.hasChildren && expanded.has(entry.node.id)) focusRow(Math.min(last, currentIndex + 1));
      return;
    }
    if (event.key === "ArrowLeft") {
      event.preventDefault();
      if (entry.hasChildren && expanded.has(entry.node.id)) toggle(entry.node.id);
      return;
    }
    if (event.key === "Home") {
      event.preventDefault();
      focusRow(0);
      return;
    }
    if (event.key === "End") {
      event.preventDefault();
      focusRow(last);
      return;
    }
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onSelect?.(entry.node.id);
      if (entry.hasChildren) toggle(entry.node.id);
    }
  };

  return (
    <div className="tree" role="tree" aria-label={ariaLabel}>
      {visible.map((entry, index) => {
        const isSelected = entry.node.id === selectedId;
        const isExpanded = entry.hasChildren ? expanded.has(entry.node.id) : undefined;
        return (
          <button
            key={entry.node.id}
            ref={(node) => { itemRefs.current[index] = node; }}
            type="button"
            role="treeitem"
            aria-level={entry.level}
            aria-selected={isSelected}
            aria-expanded={isExpanded}
            tabIndex={index === activeIndex ? 0 : -1}
            className={`tree-row ${entry.node.rail ? `rail-border--${entry.node.rail}` : ""} ${isSelected ? "is-selected" : ""}`.trim()}
            data-level={entry.level}
            onKeyDown={(event) => onKeyDown(event, index, entry)}
            onClick={() => {
              onSelect?.(entry.node.id);
              if (entry.hasChildren) toggle(entry.node.id);
            }}
          >
            {entry.hasChildren ? (
              <ChevronRight
                size={13}
                aria-hidden="true"
                className={`tree-chevron ${isExpanded ? "is-open" : ""}`.trim()}
              />
            ) : (
              <span className="tree-chevron-spacer" aria-hidden="true" />
            )}
            {renderRow ? (
              renderRow(entry.node, {
                level: entry.level,
                hasChildren: entry.hasChildren,
                isSelected,
                isExpanded,
                index,
              })
            ) : (
              <>
                {entry.node.icon ?? null}
                <span className="tree-label">{entry.node.label}</span>
              </>
            )}
          </button>
        );
      })}
    </div>
  );
}
