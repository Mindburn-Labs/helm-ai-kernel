import React, { useState } from 'react';
import { Columns, List } from 'lucide-react';

export interface VisualCodeDiffProps {
  readonly diffLines: readonly string[];
  readonly title?: string;
  readonly filename?: string;
}

interface ParsedLine {
  type: 'addition' | 'deletion' | 'normal' | 'meta';
  content: string;
  leftLineNum?: number;
  rightLineNum?: number;
}

/**
 * Enterprise-scale SOTA Visual Code Diff Component.
 * Parses and visualizes TOML/Code policy modifications with premium aesthetics,
 * offering both Split (side-by-side) and Unified views.
 */
export function VisualCodeDiff({ diffLines = [], title = "Policy Changes", filename = "policy.toml" }: VisualCodeDiffProps) {
  const [viewMode, setViewMode] = useState<'split' | 'unified'>('unified');

  // Parse lines of diff
  const parsedLines: ParsedLine[] = [];
  let leftLineCount = 1;
  let rightLineCount = 1;

  diffLines.forEach((line) => {
    if (line.startsWith('+') && !line.startsWith('+++')) {
      parsedLines.push({
        type: 'addition',
        content: line.slice(1),
        rightLineNum: rightLineCount++,
      });
    } else if (line.startsWith('-') && !line.startsWith('---')) {
      parsedLines.push({
        type: 'deletion',
        content: line.slice(1),
        leftLineNum: leftLineCount++,
      });
    } else if (line.startsWith('@@')) {
      parsedLines.push({
        type: 'meta',
        content: line,
      });
      // Parse starting line numbers if available, e.g. @@ -1,5 +1,6 @@
      const match = line.match(/@@\s+-(\d+),?\d*\s+\+(\d+),?\d*\s+@@/);
      if (match) {
        leftLineCount = parseInt(match[1], 10);
        rightLineCount = parseInt(match[2], 10);
      }
    } else {
      // Normal unchanged line (or header)
      const content = line.startsWith(' ') ? line.slice(1) : line;
      if (line.startsWith('---') || line.startsWith('+++') || line.startsWith('diff')) {
        parsedLines.push({
          type: 'meta',
          content: line,
        });
      } else {
        parsedLines.push({
          type: 'normal',
          content,
          leftLineNum: leftLineCount++,
          rightLineNum: rightLineCount++,
        });
      }
    }
  });

  // Separate left and right side lines for Split View
  const splitLeft: ParsedLine[] = [];
  const splitRight: ParsedLine[] = [];

  let idx = 0;
  while (idx < parsedLines.length) {
    const line = parsedLines[idx];
    if (line.type === 'meta') {
      splitLeft.push(line);
      splitRight.push(line);
      idx++;
    } else if (line.type === 'deletion') {
      // Collect sequential deletions and additions to align them
      const deletions: ParsedLine[] = [line];
      const additions: ParsedLine[] = [];
      let nextIdx = idx + 1;
      while (nextIdx < parsedLines.length && parsedLines[nextIdx].type === 'deletion') {
        deletions.push(parsedLines[nextIdx]);
        nextIdx++;
      }
      while (nextIdx < parsedLines.length && parsedLines[nextIdx].type === 'addition') {
        additions.push(parsedLines[nextIdx]);
        nextIdx++;
      }
      
      const maxCount = Math.max(deletions.length, additions.length);
      for (let i = 0; i < maxCount; i++) {
        if (i < deletions.length) {
          splitLeft.push(deletions[i]);
        } else {
          splitLeft.push({ type: 'normal', content: '', leftLineNum: undefined }); // Empty spacer
        }

        if (i < additions.length) {
          splitRight.push(additions[i]);
        } else {
          splitRight.push({ type: 'normal', content: '', rightLineNum: undefined }); // Empty spacer
        }
      }
      idx = nextIdx;
    } else if (line.type === 'addition') {
      // Unpaired addition
      splitLeft.push({ type: 'normal', content: '', leftLineNum: undefined });
      splitRight.push(line);
      idx++;
    } else {
      splitLeft.push(line);
      splitRight.push(line);
      idx++;
    }
  }

  return (
    <div className="visual-diff-card" style={{
      background: 'var(--color-glass-bg, rgba(14, 18, 24, 0.72))',
      backdropFilter: 'blur(20px) saturate(180%)',
      border: '1px solid var(--color-glass-border, rgba(255, 255, 255, 0.1))',
      borderRadius: '12px',
      overflow: 'hidden',
      marginTop: '16px',
      marginBottom: '16px',
      boxShadow: 'var(--shadow-large, 0 10px 30px rgba(0, 0, 0, 0.25))'
    }}>
      {/* Diff Header */}
      <div className="diff-header" style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        padding: '12px 16px',
        borderBottom: '1px solid var(--color-glass-border, rgba(255, 255, 255, 0.1))',
        background: 'rgba(255, 255, 255, 0.02)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{
            fontFamily: 'monospace',
            fontSize: '11px',
            background: 'var(--color-neutral-subtle, rgba(255, 255, 255, 0.08))',
            padding: '3px 8px',
            borderRadius: '4px',
            color: 'var(--color-neutral-text, #a8b3c2)',
            fontWeight: 'bold'
          }}>TOML DIFF</span>
          <strong style={{ fontSize: '14px', color: '#e6ecf2', fontFamily: 'monospace' }}>{filename}</strong>
          <span style={{ fontSize: '12px', color: 'var(--color-neutral-text, #8b97a7)', marginLeft: '12px' }}>{title}</span>
        </div>
        
        {/* Toggle Switch */}
        <div style={{
          display: 'flex',
          background: 'rgba(0, 0, 0, 0.2)',
          borderRadius: '6px',
          padding: '2px',
          border: '1px solid rgba(255, 255, 255, 0.05)'
        }}>
          <button
            type="button"
            onClick={() => setViewMode('unified')}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              border: 'none',
              background: viewMode === 'unified' ? 'rgba(255, 255, 255, 0.08)' : 'transparent',
              color: viewMode === 'unified' ? '#fff' : '#8b97a7',
              fontSize: '12px',
              padding: '12px 16px',
              minHeight: '44px',
              borderRadius: '4px',
              cursor: 'pointer',
              fontWeight: '500',
              transition: 'all 0.2s ease'
            }}
          >
            <List size={13} />
            Unified
          </button>
          <button
            type="button"
            onClick={() => setViewMode('split')}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              border: 'none',
              background: viewMode === 'split' ? 'rgba(255, 255, 255, 0.08)' : 'transparent',
              color: viewMode === 'split' ? '#fff' : '#8b97a7',
              fontSize: '12px',
              padding: '12px 16px',
              minHeight: '44px',
              borderRadius: '4px',
              cursor: 'pointer',
              fontWeight: '500',
              transition: 'all 0.2s ease'
            }}
          >
            <Columns size={13} />
            Split
          </button>
        </div>
      </div>

      {/* Diff Table content */}
      <div className="diff-body" style={{ overflowX: 'auto' }}>
        {viewMode === 'unified' ? (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontFamily: 'monospace', fontSize: '13px', borderSpacing: 0 }}>
            <colgroup>
              <col style={{ width: '50px' }} />
              <col style={{ width: '50px' }} />
              <col style={{ width: '25px' }} />
              <col />
            </colgroup>
            <tbody>
              {parsedLines.map((line, idx) => {
                let rowBg = 'transparent';
                let rowColor = '#e6ecf2';
                let sign = ' ';
                let signColor = '#8b97a7';

                if (line.type === 'addition') {
                  rowBg = 'rgba(63, 185, 132, 0.12)';
                  rowColor = '#a6e22e';
                  sign = '+';
                  signColor = '#3fb984';
                } else if (line.type === 'deletion') {
                  rowBg = 'rgba(229, 72, 77, 0.12)';
                  rowColor = '#f92672';
                  sign = '-';
                  signColor = '#e5484d';
                } else if (line.type === 'meta') {
                  rowBg = 'rgba(255, 255, 255, 0.02)';
                  rowColor = '#75b4ff';
                }

                return (
                  <tr key={idx} style={{ background: rowBg, color: rowColor }}>
                    <td style={{
                      textAlign: 'right',
                      padding: '2px 8px',
                      color: 'rgba(255, 255, 255, 0.25)',
                      borderRight: '1px solid rgba(255, 255, 255, 0.05)',
                      userSelect: 'none',
                      fontSize: '11px'
                    }}>{line.leftLineNum || ''}</td>
                    <td style={{
                      textAlign: 'right',
                      padding: '2px 8px',
                      color: 'rgba(255, 255, 255, 0.25)',
                      borderRight: '1px solid rgba(255, 255, 255, 0.05)',
                      userSelect: 'none',
                      fontSize: '11px'
                    }}>{line.rightLineNum || ''}</td>
                    <td style={{
                      textAlign: 'center',
                      padding: '2px 0',
                      color: signColor,
                      fontWeight: 'bold',
                      userSelect: 'none'
                    }}>{sign}</td>
                    <td style={{
                      padding: '2px 12px',
                      whiteSpace: 'pre-wrap',
                      wordBreak: 'break-all'
                    }}>{line.content}</td>
                  </tr>
                );
              })}
              {parsedLines.length === 0 ? (
                <tr>
                  <td colSpan={4} style={{ padding: '24px', textAlign: 'center', color: '#8b97a7' }}>No changes to visualize.</td>
                </tr>
              ) : null}
            </tbody>
          </table>
        ) : (
          /* Split view - Side by Side */
          <div style={{ display: 'flex', minWidth: '800px' }}>
            {/* Left Side (Deletions) */}
            <div style={{ width: '50%', borderRight: '1px solid var(--color-glass-border, rgba(255, 255, 255, 0.1))' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontFamily: 'monospace', fontSize: '13px' }}>
                <colgroup>
                  <col style={{ width: '45px' }} />
                  <col />
                </colgroup>
                <tbody>
                  {splitLeft.map((line, idx) => {
                    let rowBg = 'transparent';
                    let rowColor = '#e6ecf2';
                    if (line.type === 'deletion') {
                      rowBg = 'rgba(229, 72, 77, 0.12)';
                      rowColor = '#f92672';
                    } else if (line.type === 'meta') {
                      rowBg = 'rgba(255, 255, 255, 0.02)';
                      rowColor = '#75b4ff';
                    }

                    return (
                      <tr key={idx} style={{ background: rowBg, color: rowColor, height: '22px' }}>
                        <td style={{
                          textAlign: 'right',
                          padding: '2px 8px',
                          color: 'rgba(255, 255, 255, 0.25)',
                          borderRight: '1px solid rgba(255, 255, 255, 0.05)',
                          userSelect: 'none',
                          fontSize: '11px'
                        }}>{line.leftLineNum || ''}</td>
                        <td style={{
                          padding: '2px 12px',
                          whiteSpace: 'pre-wrap',
                          wordBreak: 'break-all'
                        }}>{line.content}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Right Side (Additions) */}
            <div style={{ width: '50%' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontFamily: 'monospace', fontSize: '13px' }}>
                <colgroup>
                  <col style={{ width: '45px' }} />
                  <col />
                </colgroup>
                <tbody>
                  {splitRight.map((line, idx) => {
                    let rowBg = 'transparent';
                    let rowColor = '#e6ecf2';
                    if (line.type === 'addition') {
                      rowBg = 'rgba(63, 185, 132, 0.12)';
                      rowColor = '#a6e22e';
                    } else if (line.type === 'meta') {
                      rowBg = 'rgba(255, 255, 255, 0.02)';
                      rowColor = '#75b4ff';
                    }

                    return (
                      <tr key={idx} style={{ background: rowBg, color: rowColor, height: '22px' }}>
                        <td style={{
                          textAlign: 'right',
                          padding: '2px 8px',
                          color: 'rgba(255, 255, 255, 0.25)',
                          borderRight: '1px solid rgba(255, 255, 255, 0.05)',
                          userSelect: 'none',
                          fontSize: '11px'
                        }}>{line.rightLineNum || ''}</td>
                        <td style={{
                          padding: '2px 12px',
                          whiteSpace: 'pre-wrap',
                          wordBreak: 'break-all'
                        }}>{line.content}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
