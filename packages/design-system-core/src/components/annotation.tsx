import React, { useState } from 'react';
import { Sparkles, Check, AlertTriangle, ArrowRight, Loader2 } from 'lucide-react';

export interface CodeAnnotation {
  readonly line: number;
  readonly text: string;
  readonly type: 'warning' | 'info' | 'error';
  readonly fixSuggestion?: string;
  readonly fixLabel?: string;
}

export interface AnnotatedCodeBlockProps {
  readonly code: string;
  readonly language?: string;
  readonly annotations?: readonly CodeAnnotation[];
  readonly onApplyFix?: (annotation: CodeAnnotation) => Promise<void> | void;
}

/**
 * Enterprise-scale SOTA Annotated Code Block Component (OpenAI Canvas style).
 * Renders custom code, policy profiles, or audit logs with inline assistant-injected
 * annotations, threat indicators, and single-click structural fix actions.
 */
export function AnnotatedCodeBlock({ 
  code, 
  language = 'toml', 
  annotations = [], 
  onApplyFix 
}: AnnotatedCodeBlockProps) {
  const [applyingFixId, setApplyingFixId] = useState<string | null>(null);
  const [appliedFixes, setAppliedFixes] = useState<Set<string>>(new Set());

  const lines = code.split('\n');

  const handleApplyFix = async (annotation: CodeAnnotation, key: string) => {
    if (!onApplyFix) return;
    setApplyingFixId(key);
    try {
      await onApplyFix(annotation);
      setAppliedFixes((prev) => {
        const next = new Set(prev);
        next.add(key);
        return next;
      });
    } catch (err) {
      console.error("Failed to apply security fix", err);
    } finally {
      setApplyingFixId(null);
    }
  };

  return (
    <div className="annotated-code-card" style={{
      background: 'var(--color-glass-bg, rgba(14, 18, 24, 0.72))',
      backdropFilter: 'blur(20px) saturate(180%)',
      border: '1px solid var(--color-glass-border, rgba(255, 255, 255, 0.1))',
      borderRadius: '12px',
      overflow: 'hidden',
      boxShadow: 'var(--shadow-large, 0 10px 30px rgba(0, 0, 0, 0.25))',
      fontFamily: 'monospace',
      fontSize: '13px',
      color: '#e6ecf2'
    }}>
      <div className="code-header" style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        padding: '8px 16px',
        borderBottom: '1px solid var(--color-glass-border, rgba(255, 255, 255, 0.1))',
        background: 'rgba(255, 255, 255, 0.02)',
        fontSize: '12px',
        color: '#8b97a7'
      }}>
        <span>Governed policy view ({language})</span>
        <span style={{ display: 'flex', alignItems: 'center', gap: '4px', color: '#66fcf1' }}>
          <Sparkles size={12} /> AI Assisted Verification Active
        </span>
      </div>

      <div className="code-container" style={{ position: 'relative', overflowX: 'auto', padding: '12px 0' }}>
        {lines.map((lineContent, index) => {
          const lineNum = index + 1;
          const matchingAnnotations = annotations.filter((ann) => ann.line === lineNum);

          return (
            <React.Fragment key={index}>
              {/* Main Code Line */}
              <div className="code-line-row" style={{
                display: 'flex',
                background: matchingAnnotations.length > 0 ? 'rgba(255, 175, 0, 0.04)' : 'transparent',
                transition: 'background 0.2s ease',
                width: '100%'
              }}>
                {/* Line Number gutter */}
                <div className="code-line-number" style={{
                  width: '45px',
                  minWidth: '45px',
                  textAlign: 'right',
                  paddingRight: '12px',
                  color: matchingAnnotations.length > 0 ? '#ffaf00' : 'rgba(255, 255, 255, 0.25)',
                  userSelect: 'none',
                  borderRight: '1px solid rgba(255, 255, 255, 0.05)',
                  fontSize: '11px'
                }}>{lineNum}</div>
                
                {/* Line content */}
                <pre className="code-line-content" style={{
                  margin: 0,
                  padding: '1px 12px',
                  whiteSpace: 'pre',
                  color: matchingAnnotations.length > 0 ? '#ffe0a3' : '#e6ecf2',
                  flex: 1
                }}>{lineContent || ' '}</pre>
              </div>

              {/* Injected Annotations under the matching line */}
              {matchingAnnotations.map((ann, annIdx) => {
                const fixKey = `${lineNum}-${annIdx}`;
                const isApplying = applyingFixId === fixKey;
                const isApplied = appliedFixes.has(fixKey);

                let tintColor = '#75b4ff'; // Info Blue
                let tintBg = 'rgba(117, 180, 255, 0.08)';
                let tintBorder = 'rgba(117, 180, 255, 0.25)';

                if (ann.type === 'error') {
                  tintColor = '#e5484d'; // Red
                  tintBg = 'rgba(229, 72, 77, 0.08)';
                  tintBorder = 'rgba(229, 72, 77, 0.25)';
                } else if (ann.type === 'warning') {
                  tintColor = '#ffaf00'; // Amber
                  tintBg = 'rgba(255, 175, 0, 0.08)';
                  tintBorder = 'rgba(255, 175, 0, 0.25)';
                }

                return (
                  <div key={annIdx} className="inline-annotation-container" style={{
                    display: 'flex',
                    background: 'rgba(0, 0, 0, 0.15)',
                    borderLeft: `3px solid ${tintColor}`,
                    margin: '6px 12px 6px 57px',
                    borderRadius: '6px',
                    overflow: 'hidden'
                  }}>
                    <div style={{
                      display: 'flex',
                      flexDirection: 'column',
                      padding: '12px 14px',
                      width: '100%',
                      gap: '8px'
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: tintColor, fontSize: '12px', fontWeight: 'bold' }}>
                        <Sparkles size={14} style={{ color: '#66fcf1' }} />
                        <span>AI Boundary Analysis:</span>
                        <span style={{
                          background: tintBg,
                          border: `1px solid ${tintBorder}`,
                          padding: '1px 6px',
                          borderRadius: '4px',
                          fontSize: '10px',
                          textTransform: 'uppercase',
                          letterSpacing: '0.5px'
                        }}>{ann.type}</span>
                      </div>
                      
                      <div style={{ color: '#a8b3c2', fontSize: '12px', lineHeight: '1.4', fontFamily: 'sans-serif' }}>
                        {ann.text}
                      </div>

                      {/* Optional inline fix suggestion */}
                      {ann.fixSuggestion && onApplyFix ? (
                        <div style={{
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          background: 'rgba(255, 255, 255, 0.01)',
                          border: '1px solid rgba(255, 255, 255, 0.05)',
                          borderRadius: '6px',
                          padding: '8px 10px',
                          marginTop: '4px'
                        }}>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                            <span style={{ fontSize: '9px', textTransform: 'uppercase', color: '#8b97a7', letterSpacing: '0.5px' }}>Fix Action Code</span>
                            <code style={{ fontSize: '11px', color: '#66fcf1', fontFamily: 'monospace' }}>{ann.fixLabel || ann.fixSuggestion}</code>
                          </div>
                          
                          <button
                            type="button"
                            disabled={isApplying || isApplied}
                            onClick={() => handleApplyFix(ann, fixKey)}
                            style={{
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'center',
                              gap: '6px',
                              border: 'none',
                              background: isApplied ? 'rgba(63, 185, 132, 0.15)' : 'rgba(102, 252, 241, 0.12)',
                              color: isApplied ? '#3fb984' : '#66fcf1',
                              fontSize: '11px',
                              padding: '12px 16px',
                              minHeight: '44px',
                              minWidth: '100px',
                              borderRadius: '4px',
                              cursor: isApplied ? 'default' : 'pointer',
                              fontWeight: 'bold',
                              transition: 'all 0.2s ease'
                            }}
                          >
                            {isApplying ? (
                              <>
                                <Loader2 size={12} className="spin" />
                                Applying...
                              </>
                            ) : isApplied ? (
                              <>
                                <Check size={12} />
                                Applied
                              </>
                            ) : (
                              <>
                                Apply Fix
                                <ArrowRight size={12} />
                              </>
                            )}
                          </button>
                        </div>
                      ) : null}
                    </div>
                  </div>
                );
              })}
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
}
