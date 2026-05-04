# Contrast table

Derived from `packages/design-system-core/src/styles/tokens.css`.
Refresh this table when token color values change, and keep token parity covered by `cd packages/design-system-core && npm test`.

Floor: 4.5:1 for body text (WCAG 1.4.3 AA), 3.0:1 for large/UI text and
non-text contrast (WCAG 1.4.11). Verdict / proof colors checked against
the surface they appear on; raw color-vs-color contrast is informational.

## dark

| Pair | Text | Background | Ratio | Floor | Pass |
|---|---|---|---:|---:|:---:|
| primary on root | `--helm-text-primary` (#e6ecf2) | `--helm-bg-root` (#07090c) | 16.75:1 | 4.5:1 | ✅ |
| primary on surface | `--helm-text-primary` (#e6ecf2) | `--helm-bg-surface` (#0b0f14) | 16.15:1 | 4.5:1 | ✅ |
| primary on elevated | `--helm-text-primary` (#e6ecf2) | `--helm-bg-elevated` (#11161d) | 15.26:1 | 4.5:1 | ✅ |
| secondary on surface | `--helm-text-secondary` (#a8b3c2) | `--helm-bg-surface` (#0b0f14) | 9.05:1 | 4.5:1 | ✅ |
| muted on surface | `--helm-text-muted` (#8b97a7) | `--helm-bg-surface` (#0b0f14) | 6.48:1 | 3.0:1 | ✅ |
| muted on root | `--helm-text-muted` (#8b97a7) | `--helm-bg-root` (#07090c) | 6.72:1 | 3.0:1 | ✅ |
| verdict-allow on surface | `--helm-verdict-allow` (#3fb984) | `--helm-bg-surface` (#0b0f14) | 7.76:1 | 3.0:1 | ✅ |
| verdict-deny on surface | `--helm-verdict-deny` (#e5484d) | `--helm-bg-surface` (#0b0f14) | 4.91:1 | 3.0:1 | ✅ |
| verdict-escalate on surface | `--helm-verdict-escalate` (#f5a524) | `--helm-bg-surface` (#0b0f14) | 9.42:1 | 3.0:1 | ✅ |
| proof-hash on surface | `--helm-proof-hash` (#75b4ff) | `--helm-bg-surface` (#0b0f14) | 8.90:1 | 3.0:1 | ✅ |

## light

| Pair | Text | Background | Ratio | Floor | Pass |
|---|---|---|---:|---:|:---:|
| primary on root | `--helm-text-primary` (#14181f) | `--helm-bg-root` (#eceef1) | 15.31:1 | 4.5:1 | ✅ |
| primary on surface | `--helm-text-primary` (#14181f) | `--helm-bg-surface` (#f4f6f8) | 16.42:1 | 4.5:1 | ✅ |
| primary on elevated | `--helm-text-primary` (#14181f) | `--helm-bg-elevated` (#ffffff) | 17.79:1 | 4.5:1 | ✅ |
| secondary on surface | `--helm-text-secondary` (#495566) | `--helm-bg-surface` (#f4f6f8) | 6.99:1 | 4.5:1 | ✅ |
| muted on surface | `--helm-text-muted` (#647082) | `--helm-bg-surface` (#f4f6f8) | 4.64:1 | 3.0:1 | ✅ |
| muted on root | `--helm-text-muted` (#647082) | `--helm-bg-root` (#eceef1) | 4.32:1 | 3.0:1 | ✅ |
| verdict-allow on surface | `--helm-verdict-allow` (#1f8a5f) | `--helm-bg-surface` (#f4f6f8) | 3.99:1 | 3.0:1 | ✅ |
| verdict-deny on surface | `--helm-verdict-deny` (#c42828) | `--helm-bg-surface` (#f4f6f8) | 5.27:1 | 3.0:1 | ✅ |
| verdict-escalate on surface | `--helm-verdict-escalate` (#9b6a05) | `--helm-bg-surface` (#f4f6f8) | 4.35:1 | 3.0:1 | ✅ |
| proof-hash on surface | `--helm-proof-hash` (#2e5bb7) | `--helm-bg-surface` (#f4f6f8) | 5.88:1 | 3.0:1 | ✅ |
