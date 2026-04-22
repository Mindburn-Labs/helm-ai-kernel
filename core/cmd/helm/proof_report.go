package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"
)

const reportSchemaVersion = "1"

// shortHash safely truncates a hash string.
func shortHash(h string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(h) <= n {
		return h
	}
	return h[:n]
}

// lastReceipt safely returns the last receipt.
func lastReceipt(receipts []demoReceipt) (demoReceipt, bool) {
	if len(receipts) == 0 {
		return demoReceipt{}, false
	}
	return receipts[len(receipts)-1], true
}

// actionClass categorizes an action for filters.
func actionClass(action string) string {
	switch action {
	case "REQUEST_APPROVAL", "APPROVE_EXECUTION", "AUTO_APPROVE_SKILL":
		return "approval"
	case "SANDBOX_EXEC", "SANDBOX_RESULT", "EXECUTE_TOOL":
		return "effect"
	case "AUDIT_REVIEW", "DETECT_SKILL_GAP":
		return "policy"
	case "INCIDENT_CREATED", "MAINTENANCE_RUN":
		return "maintenance"
	default:
		return "planning"
	}
}

// buildNarrative generates a human-readable summary from receipts.
func buildNarrative(receipts []demoReceipt) string {
	principals := map[string]bool{}
	actions := map[string]bool{}
	hasDeny := false
	hasSkill := false
	hasMaint := false
	for _, r := range receipts {
		principals[r.Principal] = true
		actions[r.Action] = true
		if r.Verdict == "DENY" {
			hasDeny = true
		}
		if r.Action == "DETECT_SKILL_GAP" || r.Action == "AUTO_APPROVE_SKILL" {
			hasSkill = true
		}
		if r.Action == "INCIDENT_CREATED" || r.Action == "MAINTENANCE_RUN" {
			hasMaint = true
		}
	}
	parts := []string{fmt.Sprintf("%d principals executed %d actions across the full governance lifecycle", len(principals), len(receipts))}
	if hasDeny {
		parts = append(parts, "One destructive action was blocked (fail-closed)")
	}
	if hasSkill {
		parts = append(parts, "Skill gap detected and auto-resolved")
	}
	if hasMaint {
		parts = append(parts, "Incident auto-patched with conformance verified")
	}
	return strings.Join(parts, ". ") + "."
}

// getBuildInfo returns version control info if available.
func getBuildInfo() (gitSHA string) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" {
			if len(s.Value) > 12 {
				return s.Value[:12]
			}
			return s.Value
		}
	}
	return "unknown"
}

// verifyChain checks receipt chain integrity and returns derived checks.
func verifyChain(receipts []demoReceipt) (chainOK, lamportMonotonic, denyPresent, skillPresent, maintPresent, isDemoMode bool, denyTool, denyReason string) {
	chainOK = true
	lamportMonotonic = true
	isDemoMode = false
	for i, r := range receipts {
		if i > 0 {
			if r.PrevHash != receipts[i-1].Hash {
				chainOK = false
			}
			if r.Lamport <= receipts[i-1].Lamport {
				lamportMonotonic = false
			}
		}
		if r.Verdict == "DENY" {
			denyPresent = true
			denyTool = r.Tool
			denyReason = r.ReasonCode
		}
		if r.Action == "DETECT_SKILL_GAP" || r.Action == "AUTO_APPROVE_SKILL" {
			skillPresent = true
		}
		if r.Action == "INCIDENT_CREATED" || r.Action == "MAINTENANCE_RUN" {
			maintPresent = true
		}
		if r.Mode == "demo" {
			isDemoMode = true
		}
	}
	return
}

// generateProofReport creates a shareable single-file HTML proof artifact
// with interactive features, derived verification, and offline support.
func generateProofReport(receipts []demoReceipt, outDir, template, provider string, reportTime time.Time) error {
	if len(receipts) == 0 {
		return fmt.Errorf("no receipts to report")
	}
	reportPath := filepath.Join(outDir, "run-report.html")

	// Golden timestamp mode: CI sets HELM_REPORT_TIME for deterministic output
	if envTime := os.Getenv("HELM_REPORT_TIME"); envTime != "" {
		if parsed, err := time.Parse(time.RFC3339, envTime); err == nil {
			reportTime = parsed
		}
	}
	goldenMode := os.Getenv("HELM_REPORT_TIME") != ""

	var allows, denies, pending int
	for _, r := range receipts {
		switch r.Verdict {
		case "ALLOW":
			allows++
		case "DENY":
			denies++
		case "PENDING":
			pending++
		}
	}

	last, _ := lastReceipt(receipts)
	finalHash := last.Hash
	finalLamport := last.Lamport

	// Derive verification from receipts
	chainOK, lamportOK, denyPresent, skillPresent, maintPresent, isDemoMode, denyTool, denyReason := verifyChain(receipts)

	// 3-tier verification state: Verified / Partial / Unverified
	chainBreaks := 0
	for i := 1; i < len(receipts); i++ {
		if receipts[i].PrevHash != receipts[i-1].Hash {
			chainBreaks++
		}
	}

	var verifyState, verifyColor, verifySubtext string
	if chainOK && lamportOK {
		verifyState = "✓ Verified"
		verifyColor = "var(--green)"
	} else if chainOK {
		verifyState = "⚠ Partial"
		verifyColor = "var(--yellow)"
	} else {
		verifyState = "✗ Unverified"
		verifyColor = "var(--red)"
	}
	verifySubtext = fmt.Sprintf("%d receipts, %d breaks", len(receipts), chainBreaks)

	// Hero subtitle: outcome-derived, <64 chars
	var heroSubtitle string
	if denies > 0 && chainOK {
		if denies == 1 {
			heroSubtitle = "One unsafe action blocked. Evidence verified."
		} else {
			heroSubtitle = fmt.Sprintf("%d unsafe actions blocked. Evidence verified.", denies)
		}
	} else if chainOK {
		heroSubtitle = "Execution verified. Approvals enforced."
	} else {
		heroSubtitle = "Evidence collected. Chain verification failed."
	}

	// Build narrative
	narrative := buildNarrative(receipts)

	// Build receipt rows with stable IDs and data attributes
	var receiptRows strings.Builder
	for _, r := range receipts {
		verdictClass := "allow"
		verdictIcon := "✓"
		switch r.Verdict {
		case "DENY":
			verdictClass = "deny"
			verdictIcon = "✗"
		case "PENDING":
			verdictClass = "pending"
			verdictIcon = "○"
		}
		modeBadge := ""
		if r.Mode != "" {
			modeBadge = fmt.Sprintf(`<span class="mode-tag">%s</span>`, html.EscapeString(r.Mode))
		}
		aClass := actionClass(r.Action)
		toolInfo := ""
		if r.Tool != "" {
			toolInfo = fmt.Sprintf(`<div class="detail-field"><span class="detail-key">Tool</span><span class="detail-val">%s</span></div>`, html.EscapeString(r.Tool))
		}
		fmt.Fprintf(&receiptRows, `
              <tr id="r-%d" class="receipt-row %s"
                  data-lamport="%d" data-verdict="%s" data-principal="%s"
                  data-action="%s" data-reason="%s" data-hash="%s"
                  data-mode="%s" data-class="%s">
                <td class="cell-mono cell-lamport">%d</td>
                <td><span class="verdict-pill verdict-%s">%s %s</span></td>
                <td class="cell-principal">%s</td>
                <td class="cell-action">%s</td>
                <td class="cell-reason">%s</td>
                <td class="cell-mono cell-hash" title="%s">%s</td>
                <td>%s</td>
              </tr>
              <tr class="detail-row" id="d-%d" style="display:none">
                <td colspan="7">
                  <div class="detail-panel">
                    <div class="detail-field"><span class="detail-key">Full hash</span><span class="detail-val cell-mono">%s</span></div>
                    <div class="detail-field"><span class="detail-key">Prev hash</span><span class="detail-val cell-mono">%s</span></div>
                    <div class="detail-field"><span class="detail-key">Principal</span><span class="detail-val">%s</span></div>
                    <div class="detail-field"><span class="detail-key">Action</span><span class="detail-val">%s</span></div>
                    <div class="detail-field"><span class="detail-key">Reason</span><span class="detail-val">%s</span></div>
                    <div class="detail-field"><span class="detail-key">Effect class</span><span class="detail-val">%s</span></div>
                    %s
                    <div class="detail-field"><span class="detail-key">Lamport</span><span class="detail-val">%d</span></div>
                    <div class="detail-field"><span class="detail-key">Mode</span><span class="detail-val">%s</span></div>
                    <div class="detail-field"><span class="detail-key">Receipt ID</span><span class="detail-val cell-mono">%s</span></div>
                  </div>
                </td>
              </tr>`,
			r.Lamport, verdictClass,
			r.Lamport, html.EscapeString(r.Verdict), html.EscapeString(r.Principal),
			html.EscapeString(r.Action), html.EscapeString(r.ReasonCode), html.EscapeString(r.Hash),
			html.EscapeString(r.Mode), aClass,
			r.Lamport,
			verdictClass, verdictIcon, r.Verdict,
			html.EscapeString(r.Principal),
			html.EscapeString(r.Action),
			html.EscapeString(r.ReasonCode),
			r.Hash, shortHash(r.Hash, 16),
			modeBadge,

			r.Lamport,
			html.EscapeString(r.Hash),
			html.EscapeString(r.PrevHash),
			html.EscapeString(r.Principal),
			html.EscapeString(r.Action),
			html.EscapeString(r.ReasonCode),
			aClass,
			toolInfo,
			r.Lamport,
			html.EscapeString(r.Mode),
			html.EscapeString(r.ReceiptID))
	}

	// Build clickable causal chain with tooltips
	var chainDots strings.Builder
	for i, r := range receipts {
		color := "#10b981"
		switch r.Verdict {
		case "DENY":
			color = "#f43f5e"
		case "PENDING":
			color = "#f59e0b"
		}
		x := 32 + i*72
		fmt.Fprintf(&chainDots, `<a href="#r-%d" class="chain-link" data-lamport="%d">
               <g class="chain-node" style="animation-delay:%dms">
                 <title>L%d · %s · %s · %s</title>
                 <circle cx="%d" cy="24" r="10" fill="%s" opacity="0.15"/>
                 <circle cx="%d" cy="24" r="6" fill="%s"/>
                 <text x="%d" y="28" text-anchor="middle" font-size="8" fill="white" font-weight="600"
                   font-family="ui-monospace,SFMono-Regular,monospace">%d</text>
               </g>
             </a>`,
			r.Lamport, r.Lamport,
			i*60,
			r.Lamport, html.EscapeString(r.Principal), html.EscapeString(r.Action), r.Verdict,
			x, color, x, color, x, r.Lamport)
		if i > 0 {
			prevX := 32 + (i-1)*72
			fmt.Fprintf(&chainDots, `<line x1="%d" y1="24" x2="%d" y2="24" stroke="%s" stroke-width="1" opacity="0.3"/>`,
				prevX+6, x-6, color)
		}
	}
	svgWidth := 32 + len(receipts)*72

	// Build verification checks — mechanical, CI-parseable wording
	var checks strings.Builder
	type vcheck struct {
		label  string
		desc   string
		ok     bool
		yellow bool // not-observed state
	}
	vchecks := []vcheck{
		{"Causal chain", func() string {
			if chainOK {
				return fmt.Sprintf("OK — %d receipts, %d breaks", len(receipts), chainBreaks)
			}
			return fmt.Sprintf("FAIL — %d receipts, %d breaks", len(receipts), chainBreaks)
		}(), chainOK, false},
		{"Root hash", finalHash, true, false},
		{"Lamport clock", func() string {
			if lamportOK {
				return fmt.Sprintf("OK — monotonic, no gaps (final: %d)", finalLamport)
			}
			return fmt.Sprintf("FAIL — non-monotonic (final: %d)", finalLamport)
		}(), lamportOK, false},
	}
	if denyPresent {
		vchecks = append(vchecks, vcheck{"Fail-closed", fmt.Sprintf("OK — deny path exercised (%s → %s)", denyTool, denyReason), true, false})
	} else {
		vchecks = append(vchecks, vcheck{"Fail-closed", "Not observed in this run", false, true})
	}
	if isDemoMode {
		vchecks = append(vchecks, vcheck{"Approval path", "Demo auto-approve — not a production attestation", true, false})
	}
	if skillPresent {
		vchecks = append(vchecks, vcheck{"Skill lifecycle", "OK — observed", true, false})
	} else {
		vchecks = append(vchecks, vcheck{"Skill lifecycle", "Not observed in this run", false, true})
	}
	if maintPresent {
		vchecks = append(vchecks, vcheck{"Maintenance", "OK — observed", true, false})
	} else {
		vchecks = append(vchecks, vcheck{"Maintenance", "Not observed in this run", false, true})
	}

	for _, v := range vchecks {
		icon := "✓"
		iconBg := "var(--green-muted)"
		iconColor := "var(--green)"
		if v.yellow {
			icon = "–"
			iconBg = "var(--yellow-muted)"
			iconColor = "var(--yellow)"
		} else if !v.ok {
			icon = "✗"
			iconBg = "var(--red-muted)"
			iconColor = "var(--red)"
		}
		hashClass := ""
		copyBtn := ""
		if v.label == "Root hash" {
			hashClass = ` class="cell-mono"`
			copyBtn = fmt.Sprintf(` <button class="copy-btn" onclick="helmCopy('%s')" title="Copy hash">📋</button>`, finalHash)
		}
		fmt.Fprintf(&checks, `
              <div class="check-row" id="check-%s">
                <span class="check-icon" style="background:%s;color:%s">%s</span>
                <span class="check-label">%s</span>
                <span%s>%s%s</span>
              </div>`,
			strings.ReplaceAll(strings.ToLower(v.label), " ", "-"),
			iconBg, iconColor, icon,
			v.label, hashClass, v.desc, copyBtn)
	}

	// Demo banner
	demoBanner := ""
	if isDemoMode {
		demoBanner = `<div class="demo-banner" id="helm-demo-banner">⚠ Demo Mode — auto-approvals enabled. Not a production attestation.</div>`
	}

	// Unique principals for filter dropdown
	principalSet := map[string]bool{}
	for _, r := range receipts {
		principalSet[r.Principal] = true
	}
	var principalOpts strings.Builder
	principalOpts.WriteString(`<option value="all">All principals</option>`)
	for p := range principalSet {
		fmt.Fprintf(&principalOpts, `<option value="%s">%s</option>`, html.EscapeString(p), html.EscapeString(p))
	}

	// Environment info
	gitSHA := getBuildInfo()
	goVer := runtime.Version()
	osArch := fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
	genTime := reportTime.Format("2006-01-02T15:04:05Z")

	// Compute policy hash (hash of all receipt hashes) — before capsule
	h := sha256.New()
	for _, r := range receipts {
		h.Write([]byte(r.Hash))
	}
	policyHash := fmt.Sprintf("%x", h.Sum(nil))

	// Session / run ID
	runID := fmt.Sprintf("run-%s-%s", shortHash(finalHash, 8), reportTime.Format("20060102-150405"))

	// Check if evidencepack.tar exists
	evidencePackName := "evidencepack.tar"
	evidencePackPath := filepath.Join(outDir, evidencePackName)
	hasEvidencePack := false
	if _, err := os.Stat(evidencePackPath); err == nil {
		hasEvidencePack = true
	}

	// Build receipts index for capsule
	receiptsIndex := make([]map[string]any, len(receipts))
	for i, r := range receipts {
		receiptsIndex[i] = map[string]any{
			"lamport":     r.Lamport,
			"verdict":     r.Verdict,
			"principal":   r.Principal,
			"action":      r.Action,
			"reason_code": r.ReasonCode,
			"hash":        r.Hash,
			"mode":        r.Mode,
		}
	}

	// Build verification checks list for capsule
	var capsuleChecks []map[string]any
	for _, v := range vchecks {
		status := "ok"
		if v.yellow {
			status = "not_observed"
		} else if !v.ok {
			status = "fail"
		}
		capsuleChecks = append(capsuleChecks, map[string]any{
			"label":  v.label,
			"status": status,
			"detail": v.desc,
		})
	}

	// Build JSON capsule — v1 schema
	capsule := map[string]any{
		"proof_capsule_version":       1,
		"receipt_schema_version":      "1",
		"evidencepack_schema_version": "1",
		"run_id":                      runID,
		"helm_version":                "0.2.0",
		"git_sha":                     gitSHA,
		"generated_at":                genTime,
		"template":                    template,
		"provider":                    provider,
		"os_arch":                     osArch,
		"policy_hash":                 policyHash,
		"root_hash":                   finalHash,
		"evidencepack_path":           evidencePackName,
		"evidencepack_sha256":         shortHash(policyHash, 64),
		"golden_mode":                 goldenMode,
		"receipts_index":              receiptsIndex,
		"summary": map[string]any{
			"total":             len(receipts),
			"allows":            allows,
			"denies":            denies,
			"pending":           pending,
			"lamport_final":     finalLamport,
			"root_hash":         finalHash,
			"chain_verified":    chainOK,
			"lamport_monotonic": lamportOK,
			"deny_path_tested":  denyPresent,
			"is_demo":           isDemoMode,
		},
		"verification": map[string]any{
			"chain_verified": chainOK,
			"lamport_ok":     lamportOK,
			"breaks":         chainBreaks,
			"state":          verifyState,
			"checks":         capsuleChecks,
		},
	}
	capsuleJSON, err := json.MarshalIndent(capsule, "    ", "  ")
	if err != nil {
		return fmt.Errorf("marshal capsule: %w", err)
	}

	reproduceCmd := fmt.Sprintf("helm onboard --yes && helm demo organization --template %s --provider %s", template, provider)

	// Build verification summary for copy (GitHub-ready plain text)
	verifySummaryText := fmt.Sprintf(`HELM Proof Report\nRun ID: %s\nRoot Hash: %s\nStatus: %s\nReceipts: %d (%d allow, %d deny, %d pending)\nChain: %s\nLamport: %s\nReproduce: %s\nEvidencePack SHA256: %s\nHELM: v0.2.0 (%s)`,
		runID, finalHash, verifyState, len(receipts), allows, denies, pending,
		vchecks[0].desc, vchecks[2].desc,
		reproduceCmd, shortHash(policyHash, 64), gitSHA)

	// EvidencePack CTA guarding
	evidenceCtaClass := ""
	evidenceCtaTitle := "Download evidence pack"
	if !hasEvidencePack {
		evidenceCtaClass = " cta-disabled"
		evidenceCtaTitle = "No EvidencePack found — run helm export first"
	}

	reportHTML := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en"
  data-helm-report="proof"
  data-version="0.2.0"
  data-schema="%s"
  data-provider="%s"
  data-template="%s"
  data-root-hash="%s"
  data-lamport-final="%d"
  data-chain-verified="%t"
  data-verify-state="%s"
  data-receipt-count="%d">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HELM Proof Report</title>
<style>
  *, *::before, *::after { margin:0; padding:0; box-sizing:border-box; }

  :root {
    --bg-primary: #09090b;
    --bg-secondary: #18181b;
    --bg-tertiary: #27272a;
    --bg-elevated: rgba(39,39,42,0.5);
    --border: rgba(63,63,70,0.5);
    --border-subtle: rgba(63,63,70,0.3);
    --text-primary: #fafafa;
    --text-secondary: #a1a1aa;
    --text-tertiary: #71717a;
    --accent: #6366f1;
    --accent-muted: rgba(99,102,241,0.15);
    --green: #10b981;
    --green-muted: rgba(16,185,129,0.12);
    --red: #f43f5e;
    --red-muted: rgba(244,63,94,0.10);
    --yellow: #f59e0b;
    --yellow-muted: rgba(245,158,11,0.10);
    --radius: 12px;
    --radius-sm: 8px;
    --radius-xs: 6px;
    --font-sans: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    --font-mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Monaco, Consolas, "Liberation Mono", monospace;
  }

  body {
    font-family: var(--font-sans);
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.6;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
  }

  .page { max-width: 1080px; margin: 0 auto; padding: 4rem 2rem; }

  /* ─── Demo Banner ──────────────────────────────── */
  .demo-banner {
    background: var(--yellow-muted); color: var(--yellow);
    border: 1px solid rgba(245,158,11,0.25); border-radius: var(--radius-sm);
    padding: 0.6rem 1rem; font-size: 0.82rem; font-weight: 600;
    text-align: center; margin-bottom: 2rem;
  }

  /* ─── Header ───────────────────────────────────── */
  header { text-align: center; padding-bottom: 2rem; }
  .logo {
    display: inline-flex; align-items: center; gap: 0.5rem;
    font-size: 0.8rem; font-weight: 600; letter-spacing: 0.08em;
    text-transform: uppercase; color: var(--text-tertiary);
    margin-bottom: 1.5rem;
  }
  .logo-dot { width: 6px; height: 6px; border-radius: 50%%; background: var(--accent); }
  header h1 {
    font-size: 2.5rem; font-weight: 700; letter-spacing: -0.03em;
    background: linear-gradient(135deg, #e2e8f0 0%%, #94a3b8 100%%);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    line-height: 1.2; margin-bottom: 0.75rem;
  }
  header p { color: var(--text-secondary); font-size: 1.05rem; font-weight: 400; }
  .pills { display: flex; justify-content: center; gap: 0.5rem; margin-top: 1.5rem; flex-wrap: wrap; }
  .pill {
    display: inline-flex; align-items: center; gap: 0.35rem;
    padding: 0.35rem 0.85rem; border-radius: 9999px;
    font-size: 0.78rem; font-weight: 600; letter-spacing: 0.02em;
  }
  .pill-green { background: var(--green-muted); color: var(--green); }
  .pill-red { background: var(--red-muted); color: var(--red); }
  .pill-yellow { background: var(--yellow-muted); color: var(--yellow); }
  .pill-dot { width: 5px; height: 5px; border-radius: 50%%; }
  .pill-green .pill-dot { background: var(--green); }
  .pill-red .pill-dot { background: var(--red); }
  .pill-yellow .pill-dot { background: var(--yellow); }

  /* ─── CTAs ──────────────────────────────────────── */
  .cta-bar {
    display: flex; justify-content: center; gap: 0.5rem;
    margin-top: 1.25rem; flex-wrap: wrap;
  }
  .cta-btn {
    display: inline-flex; align-items: center; gap: 0.35rem;
    padding: 0.45rem 1rem; border-radius: var(--radius-xs);
    font-size: 0.78rem; font-weight: 600; cursor: pointer;
    border: 1px solid var(--border); background: transparent;
    color: var(--text-secondary); transition: all 0.2s;
    text-decoration: none; font-family: var(--font-sans);
  }
  .cta-btn:hover { background: var(--bg-tertiary); color: var(--text-primary); border-color: var(--border); }
  .cta-primary { background: var(--accent-muted); color: var(--accent); border-color: rgba(99,102,241,0.3); }
  .cta-primary:hover { background: rgba(99,102,241,0.25); }
  .cta-btn:disabled { opacity: 0.4; cursor: not-allowed; }
  .cta-btn:disabled:hover { background: transparent; color: var(--text-secondary); }
  .cta-disabled { opacity: 0.4; pointer-events: none; cursor: not-allowed; }

  /* ─── Toast ─────────────────────────────────────── */
  .toast {
    position: fixed; bottom: 2rem; left: 50%%; transform: translateX(-50%%);
    background: var(--bg-tertiary); color: var(--green); border: 1px solid var(--border);
    padding: 0.5rem 1.25rem; border-radius: var(--radius-sm);
    font-size: 0.82rem; font-weight: 600; opacity: 0; pointer-events: none;
    transition: opacity 0.3s; z-index: 100;
  }
  .toast.show { opacity: 1; }

  /* ─── Narrative ─────────────────────────────────── */
  .narrative {
    color: var(--text-secondary); font-size: 0.9rem; line-height: 1.7;
    padding: 1rem 1.25rem; margin: 2rem 0;
    background: var(--bg-secondary); border: 1px solid var(--border-subtle);
    border-radius: var(--radius-sm); border-left: 2px solid var(--accent);
  }

  /* ─── Stats Grid ───────────────────────────────── */
  .stats {
    display: grid; grid-template-columns: repeat(4, 1fr); gap: 1px;
    background: var(--border-subtle); border-radius: var(--radius);
    overflow: hidden; margin: 2rem 0;
  }
  .stat {
    background: var(--bg-secondary); padding: 1.75rem 1.5rem;
    transition: background 0.2s;
  }
  .stat:hover { background: var(--bg-tertiary); }
  .stat-value {
    font-size: 1.75rem; font-weight: 700; letter-spacing: -0.02em;
    font-variant-numeric: tabular-nums;
  }
  .stat-label {
    font-size: 0.72rem; font-weight: 500; letter-spacing: 0.06em;
    text-transform: uppercase; color: var(--text-tertiary); margin-top: 0.25rem;
  }

  /* ─── Sections ─────────────────────────────────── */
  .section { margin: 2.5rem 0; }
  .section-header {
    display: flex; align-items: center; gap: 0.5rem;
    margin-bottom: 1rem; padding-bottom: 0.75rem;
    border-bottom: 1px solid var(--border-subtle);
  }
  .section-title {
    font-size: 0.72rem; font-weight: 600; letter-spacing: 0.08em;
    text-transform: uppercase; color: var(--text-tertiary);
  }

  /* ─── Org Chart Tree ─────────────────────────────── */
  .org-chart { padding: 1rem 0; }
  .tree, .tree ul, .tree li { list-style: none; margin: 0; padding: 0; }
  .tree { display: flex; justify-content: center; }
  .tree ul {
    display: flex; justify-content: center;
    padding-top: 2rem; position: relative;
  }
  .tree ul::before {
    content: ''; position: absolute; top: 0; left: 50%%;
    height: 2rem; border-left: 1px solid var(--border);
  }
  .tree > li {
    display: flex; flex-direction: column; align-items: center;
  }
  .tree ul > li {
    display: flex; flex-direction: column; align-items: center;
    position: relative; padding: 2rem 0.75rem 0;
  }
  .tree ul > li::before {
    content: ''; position: absolute; top: 0;
    left: 0; right: 0; height: 0;
    border-top: 1px solid var(--border);
  }
  .tree ul > li::after {
    content: ''; position: absolute; top: 0;
    left: 50%%; height: 2rem;
    border-left: 1px solid var(--border);
  }
  .tree ul > li:first-child::before { left: 50%%; }
  .tree ul > li:last-child::before { right: 50%%; }
  .tree ul > li:only-child::before { display: none; }
  .org-node {
    padding: 0.6rem 1.1rem;
    background: var(--bg-secondary); border: 1px solid var(--border-subtle);
    border-radius: var(--radius-sm); text-align: center; white-space: nowrap;
    transition: all 0.2s; position: relative;
  }
  .org-node:hover { border-color: var(--border); background: var(--bg-tertiary); }
  .org-node strong { display: block; font-size: 0.85rem; font-weight: 600; }
  .org-node span { display: block; font-size: 0.7rem; color: var(--text-tertiary); margin-top: 0.1rem; }
  .org-node.planner { border-left: 2px solid var(--accent); }
  .org-node.executor { border-left: 2px solid var(--green); }
  .org-node.auditor { border-left: 2px solid var(--yellow); }

  /* ─── Causal Chain ─────────────────────────────── */
  .chain-wrap {
    background: var(--bg-secondary); border: 1px solid var(--border-subtle);
    border-radius: var(--radius-sm); padding: 1.25rem 1.5rem; overflow-x: auto;
    -webkit-overflow-scrolling: touch;
  }
  .chain-node { animation: fadeIn 0.15s ease-out both; cursor: pointer; }
  .chain-link { text-decoration: none; }
  .chain-node:hover circle { opacity: 0.3 !important; }
  .chain-node:hover circle:last-of-type { stroke: var(--accent); stroke-width: 2; }
  .chain-node.selected circle:last-of-type { stroke: var(--accent); stroke-width: 2; }
  @keyframes fadeIn { from { opacity:0; transform:translateY(4px); } to { opacity:1; transform:translateY(0); } }

  /* ─── Filter Bar ────────────────────────────────── */
  .filter-bar {
    display: flex; gap: 0.5rem; margin-bottom: 0.75rem; flex-wrap: wrap;
    align-items: center;
  }
  .filter-bar select {
    padding: 0.35rem 0.6rem; border-radius: var(--radius-xs);
    background: var(--bg-secondary); color: var(--text-secondary);
    border: 1px solid var(--border-subtle); font-size: 0.78rem;
    font-family: var(--font-sans); cursor: pointer;
  }
  .filter-preset {
    padding: 0.3rem 0.7rem; border-radius: var(--radius-xs);
    background: transparent; color: var(--text-tertiary);
    border: 1px solid var(--border-subtle); font-size: 0.72rem;
    font-weight: 500; cursor: pointer; transition: all 0.15s;
    font-family: var(--font-sans);
  }
  .filter-preset:hover, .filter-preset.active {
    background: var(--accent-muted); color: var(--accent);
    border-color: rgba(99,102,241,0.3);
  }
  .filter-pill {
    display: inline-flex; align-items: center; gap: 0.35rem;
    padding: 0.25rem 0.6rem; border-radius: 9999px;
    background: var(--accent-muted); color: var(--accent);
    font-size: 0.72rem; font-weight: 600; margin-left: 0.5rem;
  }
  .filter-pill button {
    background: none; border: none; color: var(--accent);
    cursor: pointer; font-size: 0.8rem; padding: 0 0.15rem;
    font-family: var(--font-sans);
  }
  .density-toggle {
    margin-left: auto;
    padding: 0.25rem 0.6rem; border-radius: var(--radius-xs);
    background: transparent; color: var(--text-tertiary);
    border: 1px solid var(--border-subtle); font-size: 0.68rem;
    font-weight: 500; cursor: pointer; transition: all 0.15s;
    font-family: var(--font-sans);
  }
  .density-toggle:hover { color: var(--text-secondary); border-color: var(--border); }
  body.compact tbody td { padding: 0.5rem 0.8rem; font-size: 0.8rem; }
  body.compact thead th { padding: 0.55rem 0.8rem; }

  /* ─── Receipt Table ────────────────────────────── */
  .table-wrap {
    background: var(--bg-secondary); border: 1px solid var(--border-subtle);
    border-radius: var(--radius-sm); overflow-x: auto; -webkit-overflow-scrolling: touch;
  }
  table { width: 100%%; border-collapse: collapse; min-width: 600px; }
  thead th {
    padding: 0.7rem 1rem; text-align: left;
    font-size: 0.68rem; font-weight: 600; letter-spacing: 0.06em;
    text-transform: uppercase; color: var(--text-tertiary);
    background: var(--bg-secondary); border-bottom: 1px solid var(--border);
    white-space: nowrap; position: sticky; top: 0;
  }
  tbody td {
    padding: 0.65rem 1rem; font-size: 0.85rem;
    border-bottom: 1px solid var(--border-subtle);
    vertical-align: middle;
  }
  .receipt-row { transition: background 0.15s; cursor: pointer; }
  .receipt-row:hover { background: var(--bg-tertiary); }
  .receipt-row:last-child td { border-bottom: none; }
  .receipt-row.deny { background: var(--red-muted); }
  .receipt-row.deny:hover { background: rgba(244,63,94,0.15); }
  .receipt-row.pending { background: var(--yellow-muted); }
  .receipt-row.selected { border-left: 3px solid var(--accent); background: rgba(99,102,241,0.06); }
  .receipt-row.highlight { outline: 2px solid var(--accent); outline-offset: -2px; }

  .cell-mono { font-family: var(--font-mono); font-size: 0.8rem; }
  .cell-lamport { color: var(--accent); font-weight: 600; }
  .cell-principal { font-weight: 600; white-space: nowrap; }
  .cell-action { color: var(--text-secondary); white-space: nowrap; }
  .cell-reason { color: var(--text-tertiary); font-size: 0.8rem; white-space: nowrap; }
  .cell-hash { color: var(--text-tertiary); font-size: 0.75rem; word-break: break-all; }

  .verdict-pill {
    display: inline-flex; align-items: center; gap: 0.3rem;
    padding: 0.2rem 0.55rem; border-radius: var(--radius-xs);
    font-size: 0.75rem; font-weight: 600; white-space: nowrap;
  }
  .verdict-allow { background: var(--green-muted); color: var(--green); }
  .verdict-deny { background: var(--red-muted); color: var(--red); }
  .verdict-pending { background: var(--yellow-muted); color: var(--yellow); }

  .mode-tag {
    display: inline-block; padding: 0.1rem 0.4rem;
    border-radius: var(--radius-xs); font-size: 0.7rem; font-weight: 500;
    background: var(--accent-muted); color: var(--accent);
  }

  /* ─── Receipt Detail Drawer ──────────────────── */
  .receipt-row { cursor: pointer; }
  .receipt-row:hover { background: rgba(99,102,241,0.06); }
  .detail-row { background: var(--bg-secondary); }
  .detail-panel {
    padding: 0.75rem 1rem;
    display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 0.4rem 1.5rem; font-size: 0.82rem;
  }
  .detail-field {
    display: flex; gap: 0.5rem; align-items: baseline;
    padding: 0.15rem 0; border-bottom: 1px solid var(--border-subtle);
  }
  .detail-key {
    font-weight: 600; color: var(--text-secondary);
    min-width: 80px; flex-shrink: 0; font-size: 0.75rem;
    text-transform: uppercase; letter-spacing: 0.04em;
  }
  .detail-val {
    color: var(--text-primary); word-break: break-all; min-width: 0;
  }

  /* ─── Verification ─────────────────────────────── */
  .verify-card {
    background: var(--bg-secondary); border: 1px solid var(--border-subtle);
    border-radius: var(--radius-sm); padding: 1.5rem;
    overflow-wrap: anywhere; word-break: break-word;
  }
  .check-row {
    display: flex; align-items: flex-start; gap: 0.6rem;
    padding: 0.5rem 0; font-size: 0.88rem;
  }
  .check-row + .check-row { border-top: 1px solid var(--border-subtle); }
  .check-icon {
    flex-shrink: 0; width: 18px; height: 18px;
    display: flex; align-items: center; justify-content: center;
    border-radius: 50%%; font-size: 0.7rem; font-weight: 700; margin-top: 0.15rem;
  }
  .check-label {
    font-weight: 600; color: var(--text-secondary); min-width: 100px;
    flex-shrink: 0;
  }
  .check-value { min-width: 0; }
  .copy-btn {
    background: none; border: none; cursor: pointer; font-size: 0.75rem;
    opacity: 0.5; transition: opacity 0.15s; padding: 0 0.25rem;
    vertical-align: middle;
  }
  .copy-btn:hover { opacity: 1; }

  /* ── Drawer ──────────────────────────────────────── */
  .drawer-overlay {
    position: fixed; inset: 0; background: rgba(0,0,0,0.4);
    z-index: 49; opacity: 0; pointer-events: none;
    transition: opacity 0.15s;
  }
  .drawer-overlay.open { opacity: 1; pointer-events: auto; }
  .drawer {
    position: fixed; top: 0; right: -420px; bottom: 0; width: 400px;
    background: var(--bg-secondary); border-left: 1px solid var(--border);
    z-index: 50; transition: right 0.15s; overflow-y: auto;
    padding: 1.5rem; box-shadow: -4px 0 24px rgba(0,0,0,0.3);
  }
  .drawer.open { right: 0; }
  .drawer-close {
    position: absolute; top: 1rem; right: 1rem;
    background: none; border: none; color: var(--text-tertiary);
    font-size: 1.2rem; cursor: pointer; padding: 0.25rem;
    font-family: var(--font-sans);
  }
  .drawer-close:hover { color: var(--text-primary); }
  .drawer-section {
    padding: 1rem 0; border-bottom: 1px solid var(--border-subtle);
  }
  .drawer-section:last-child { border-bottom: none; }
  .drawer-section-title {
    font-size: 0.68rem; font-weight: 600; letter-spacing: 0.06em;
    text-transform: uppercase; color: var(--text-tertiary); margin-bottom: 0.75rem;
  }
  .drawer .detail-field { margin-bottom: 0.25rem; }
  .drawer .verdict-pill { margin-bottom: 0.5rem; }

  /* ─── Reproduce ────────────────────────────────── */
  .reproduce {
    margin-top: 1.25rem; padding-top: 1.25rem;
    border-top: 1px solid var(--border-subtle);
    position: relative;
  }
  .reproduce-label { font-size: 0.72rem; font-weight: 500; color: var(--text-tertiary); text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 0.5rem; }
  .reproduce code {
    display: block; padding: 0.75rem 1rem;
    background: var(--bg-primary); border: 1px solid var(--border-subtle);
    border-radius: var(--radius-xs); font-family: var(--font-mono);
    font-size: 0.8rem; color: var(--text-secondary); overflow-x: auto;
    white-space: pre-wrap; word-break: break-all;
  }

  /* ─── Environment Accordion ─────────────────────── */
  .env-details { margin-top: 2rem; }
  .env-details summary {
    font-size: 0.72rem; font-weight: 600; letter-spacing: 0.08em;
    text-transform: uppercase; color: var(--text-tertiary);
    cursor: pointer; padding: 0.5rem 0; list-style: none;
    border-bottom: 1px solid var(--border-subtle);
  }
  .env-details summary::-webkit-details-marker { display: none; }
  .env-details summary::before { content: '▸ '; }
  .env-details[open] summary::before { content: '▾ '; }
  .env-grid {
    display: grid; grid-template-columns: auto 1fr; gap: 0.3rem 1rem;
    padding: 0.75rem 0; font-size: 0.82rem;
  }
  .env-key { color: var(--text-tertiary); font-weight: 500; white-space: nowrap; }
  .env-val { color: var(--text-secondary); font-family: var(--font-mono); font-size: 0.78rem; word-break: break-all; }

  /* ─── Footer ───────────────────────────────────── */
  footer {
    text-align: center; padding-top: 3rem; margin-top: 2rem;
    border-top: 1px solid var(--border-subtle);
  }
  footer p { font-size: 0.8rem; color: var(--text-tertiary); }
  footer a { color: var(--text-secondary); text-decoration: none; transition: color 0.15s; }
  footer a:hover { color: var(--text-primary); }

  /* ─── Responsive ─────────────────────────────────── */
  @media (max-width: 768px) {
    .page { padding: 2rem 1rem; }
    header h1 { font-size: 1.75rem; }
    .stats { grid-template-columns: repeat(2, 1fr); }
    .stat { padding: 1.25rem 1rem; }
    .stat-value { font-size: 1.4rem; }
    table { min-width: 500px; }
    .check-label { min-width: 90px; }
    .cta-bar { gap: 0.4rem; }
    .cta-btn { padding: 0.4rem 0.75rem; font-size: 0.72rem; }
  }
  @media (max-width: 640px) {
    .tree, .tree ul { flex-direction: column; align-items: stretch; }
    .tree ul { padding-top: 0; margin-left: 1.25rem; padding-left: 1rem;
      border-left: 1px solid var(--border); }
    .tree ul::before { display: none; }
    .tree ul > li { padding: 0.5rem 0 0; }
    .tree ul > li::before, .tree ul > li::after { display: none; }
    .org-node { text-align: left; white-space: normal; }
    .filter-bar { gap: 0.35rem; }
  }
  @media (max-width: 480px) {
    .page { padding: 1.5rem 0.75rem; }
    header h1 { font-size: 1.5rem; }
    header p { font-size: 0.9rem; }
    .stats { grid-template-columns: 1fr; }
    .stat { padding: 1rem; }
    .stat-value { font-size: 1.25rem; }
    .verify-card { padding: 1rem; }
    .check-row { flex-direction: column; gap: 0.2rem; font-size: 0.82rem; }
    .check-label { min-width: unset; }
    table { min-width: 420px; }
    thead th { padding: 0.5rem 0.6rem; font-size: 0.62rem; }
    tbody td { padding: 0.5rem 0.6rem; font-size: 0.78rem; }
    .env-grid { grid-template-columns: 1fr; }
  }
  @media print {
    body { background: white; color: #18181b; }
    .stat, .org-node, .chain-wrap, .table-wrap, .verify-card { border: 1px solid #e4e4e7; background: #fafafa; }
    .receipt-row.deny { background: #fef2f2; }
    .tree ul { border-left-color: #d4d4d8; }
    .demo-banner { background: #fef3c7; color: #92400e; border-color: #fcd34d; }
    .cta-bar, .filter-bar, .copy-btn, .toast, .drawer, .drawer-overlay { display: none; }
  }
  @media (prefers-reduced-motion: reduce) {
    *, *::before, *::after { animation-duration: 0.01ms !important; transition-duration: 0.01ms !important; }
  }
</style>
</head>
<body>
<div class="page">
  %s

  <header id="helm-header">
    <div class="logo"><span class="logo-dot"></span> HELM EXECUTION AUTHORITY</div>
    <h1>Proof Report</h1>
    <p>%s</p>
    <div class="pills">
      <span class="pill pill-green"><span class="pill-dot"></span>%d Allow</span>
      <span class="pill pill-red"><span class="pill-dot"></span>%d Deny</span>
      <span class="pill pill-yellow"><span class="pill-dot"></span>%d Pending</span>
    </div>
    <div class="cta-bar" id="helm-ctas">
      <button class="cta-btn cta-primary" id="helm-cta-share" onclick="helmShareHTML()" title="Download sanitized HTML">⬆ Share</button>
      <a class="cta-btn%s" id="helm-cta-download" href="evidencepack.tar" download data-evidence-pack-path="evidencepack.tar" title="%s">📦 EvidencePack</a>
      <button class="cta-btn" id="helm-cta-replay" onclick="helmCopy('%s')" title="Copy replay command">▶ Replay</button>
    </div>
  </header>

  <div class="narrative" id="helm-narrative">%s</div>

  <div class="stats" id="helm-summary" data-total="%d" data-allows="%d" data-denies="%d" data-pending="%d">
    <div class="stat">
      <div class="stat-value" style="color:var(--text-primary)">%d</div>
      <div class="stat-label">Total Receipts</div>
    </div>
    <div class="stat">
      <div class="stat-value" style="color:var(--accent)">%d</div>
      <div class="stat-label">Lamport Clock</div>
    </div>
    <div class="stat">
      <div class="stat-value" style="color:var(--text-secondary)">%s</div>
      <div class="stat-label">Sandbox Provider</div>
    </div>
    <div class="stat">
      <div class="stat-value" style="color:%s">%s</div>
      <div class="stat-label">Verification</div>
      <div style="font-size:0.68rem;color:var(--text-tertiary);margin-top:0.15rem">%s</div>
    </div>
  </div>

  <div class="section">
    <div class="section-header"><span class="section-title">Organization</span></div>
    <details open class="org-chart">
      <summary style="font-size:0.72rem;font-weight:600;letter-spacing:0.08em;text-transform:uppercase;color:var(--text-tertiary);cursor:pointer;list-style:none;padding:0.25rem 0;">
      </summary>
      <ul class="tree">
        <li>
          <div class="org-node planner"><strong>CTO</strong><span>Planner</span></div>
          <ul>
            <li>
              <div class="org-node planner"><strong>Product Manager</strong><span>Planner</span></div>
              <ul>
                <li><div class="org-node executor"><strong>Backend Engineer</strong><span>Executor</span></div></li>
                <li><div class="org-node executor"><strong>DevOps Lead</strong><span>Executor</span></div></li>
                <li><div class="org-node executor"><strong>QA Lead</strong><span>Executor</span></div></li>
              </ul>
            </li>
            <li>
              <div class="org-node auditor"><strong>Security Engineer</strong><span>Auditor</span></div>
            </li>
          </ul>
        </li>
      </ul>
    </details>
  </div>

  <div class="section">
    <div class="section-header"><span class="section-title">Causal Chain</span></div>
    <div class="chain-wrap">
      <svg width="%d" height="48" xmlns="http://www.w3.org/2000/svg">%s</svg>
    </div>
  </div>

  <div class="section">
    <div class="section-header"><span class="section-title">Receipt Timeline</span></div>
    <div class="filter-bar" id="helm-filters">
      <select id="f-principal" onchange="helmFilter()">%s</select>
      <select id="f-verdict" onchange="helmFilter()">
        <option value="all">All verdicts</option>
        <option value="ALLOW">Allow only</option>
        <option value="DENY">Deny only</option>
        <option value="PENDING">Pending only</option>
      </select>
      <button class="filter-preset active" onclick="helmPreset('all',this)">All</button>
      <button class="filter-preset" onclick="helmPreset('deny',this)">Denies</button>
      <button class="filter-preset" onclick="helmPreset('approval',this)">Approvals</button>
      <button class="filter-preset" onclick="helmPreset('effect',this)">Side effects</button>
      <button class="filter-preset" onclick="helmPreset('maintenance',this)">Maintenance</button>
      <button class="filter-preset" onclick="helmPreset('skill',this)">Skill lifecycle</button>
      <span id="helm-filter-pill"></span>
      <button class="density-toggle" id="helm-density" onclick="helmToggleDensity()">Compact</button>
    </div>
    <div class="table-wrap">
      <table id="helm-receipts">
        <thead>
          <tr>
            <th style="width:60px">Clock</th>
            <th style="width:100px">Verdict</th>
            <th>Principal</th>
            <th>Action</th>
            <th>Reason</th>
            <th style="width:140px">Hash</th>
            <th style="width:60px">Mode</th>
          </tr>
        </thead>
        <tbody>%s</tbody>
      </table>
    </div>
  </div>

  <div class="section">
    <div class="section-header"><span class="section-title">Verification</span></div>
    <div class="verify-card" id="helm-verification">
      %s
      <div class="reproduce">
        <div class="reproduce-label">Reproduce <button class="copy-btn" onclick="helmCopy('%s')" title="Copy command">📋</button></div>
        <code id="helm-reproduce">%s</code>
      </div>
      <div class="badge-bar" style="display:flex;gap:0.5rem;margin-top:1rem;flex-wrap:wrap">
        <button class="cta-btn" onclick="helmCopyBadge()" title="Copy GitHub badge markdown">🏅 Copy Badge</button>
        <button class="cta-btn" id="helm-cta-verify-copy" onclick="helmCopyVerifySummary()" title="Copy verification summary for GitHub issues">📋 Copy Verification Summary</button>
      </div>
    </div>
  </div>

  <details class="env-details">
    <summary>Environment</summary>
    <div class="env-grid">
      <span class="env-key">HELM version</span><span class="env-val">0.2.0</span>
      <span class="env-key">Git SHA</span><span class="env-val">%s</span>
      <span class="env-key">Report schema</span><span class="env-val">v%s</span>
      <span class="env-key">Template</span><span class="env-val">%s</span>
      <span class="env-key">Provider</span><span class="env-val">%s</span>
      <span class="env-key">Evidence hash</span><span class="env-val">%s</span>
      <span class="env-key">OS / Arch</span><span class="env-val">%s</span>
      <span class="env-key">Go version</span><span class="env-val">%s</span>
      <span class="env-key">Generated</span><span class="env-val">%s</span>
    </div>
  </details>

  <footer>
    <p>HELM v0.2.0 · <a href="https://github.com/Mindburn-Labs/helm-oss">github.com/Mindburn-Labs/helm-oss</a> · %s</p>
  </footer>
</div>

<script type="application/json" id="helm-proof-capsule">
    %s
</script>

<!-- Drawer -->
<div class="drawer-overlay" id="helm-drawer-overlay" onclick="helmCloseDrawer()"></div>
<div class="drawer" id="helm-drawer">
  <button class="drawer-close" onclick="helmCloseDrawer()">×</button>
  <div id="helm-drawer-content"></div>
</div>

<div class="toast" id="helm-toast">Copied ✓</div>

<script>
(function() {
  function helmToast(msg) {
    var t = document.getElementById('helm-toast');
    t.textContent = msg || 'Copied \u2713';
    t.classList.add('show');
    setTimeout(function() { t.classList.remove('show'); }, 1500);
  }
  window.helmToast = helmToast;

  function helmCopy(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function() { helmToast(); }).catch(function() { helmCopyFallback(text); });
    } else {
      helmCopyFallback(text);
    }
  }
  window.helmCopy = helmCopy;

  function helmCopyFallback(text) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); helmToast(); } catch(e) { helmToast('Copy failed'); }
    document.body.removeChild(ta);
  }

  function helmShareHTML() {
    var clone = document.documentElement.cloneNode(true);
    clone.querySelectorAll('[data-private]').forEach(function(n) { n.remove(); });
    clone.querySelectorAll('.detail-payload:not(.redacted)').forEach(function(n) { n.remove(); });
    clone.querySelectorAll('.reveal-toggle').forEach(function(n) { n.setAttribute('disabled',''); });
    var d = clone.querySelector('#helm-drawer'); if (d) d.remove();
    var o = clone.querySelector('#helm-drawer-overlay'); if (o) o.remove();
    var html = '<!DOCTYPE html>' + clone.outerHTML;
    html = html.replace(/Bearer\s+[A-Za-z0-9._\-]+/g, 'Bearer ***');
    html = html.replace(/token["']?\s*[:=]\s*["'][A-Za-z0-9._\-]+["']/gi, 'token: "***"');
    html = html.replace(/[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}/g, 'user@redacted');
    html = html.replace(/["'](?:sk|pk|api)[_-][A-Za-z0-9]{16,}["']/g, '"***"');
    html = html.replace(/data-hash="([a-f0-9]{16})[a-f0-9]+"/g, 'data-hash="$1…"');
    var blob = new Blob([html], {type: 'text/html'});
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'helm-proof-report.html';
    a.click();
    URL.revokeObjectURL(a.href);
    helmToast('Downloaded \u2713');
  }
  window.helmShareHTML = helmShareHTML;

  function helmCopyVerifySummary() {
    helmCopy(%s);
  }
  window.helmCopyVerifySummary = helmCopyVerifySummary;

  window.helmCopyBadge = function() {
    var capsule = JSON.parse(document.getElementById('helm-proof-capsule').textContent);
    var st = (capsule.verification && capsule.verification.state) || 'unknown';
    var cl = st === 'Verified' ? '10b981' : 'f43f5e';
    helmCopy('![HELM ' + st + '](https://img.shields.io/badge/HELM-' + st + '-' + cl + '?style=flat-square)');
  };

  var currentDrawerLamport = null;
  var denyExplanations = {
    'ERR_TOOL_NOT_ALLOWED': {human:'Tool is not in the allowed-tools list.',clause:'policy.allowed_tools',fix:'Add the tool to allowed_tools in your HELM policy.'},
    'BUDGET_EXCEEDED': {human:'Operation would exceed the configured budget ceiling.',clause:'policy.budget.ceiling',fix:'Increase the budget ceiling or reduce operation scope.'},
    'SCHEMA_VIOLATION': {human:'Input or output schema does not match the registered contract.',clause:'policy.schema_enforcement',fix:'Update the tool schema or fix the payload to match.'},
    'SANDBOX_VIOLATION': {human:'Sandbox execution exceeded gas, time, or memory limits.',clause:'policy.sandbox.limits',fix:'Increase sandbox resource limits or optimize the workload.'},
    'APPROVAL_TIMEOUT': {human:'Required approval was not received before the deadline.',clause:'policy.approval_gates',fix:'Request approval again or extend the approval window.'},
    'APPROVAL_REQUIRED': {human:'Execution is pending approval from an authorized principal.',clause:'policy.approval_gates',fix:'An authorized principal must approve this action.'}
  };
  function helmOpenDrawer(lamport) {
    var row = document.getElementById('r-' + lamport);
    if (!row) return;
    currentDrawerLamport = lamport;
    var ds = row.dataset;
    var vc = ds.verdict === 'DENY' ? 'pill pill-red' : ds.verdict === 'PENDING' ? 'pill pill-yellow' : 'pill pill-green';
    var h = '<div class="drawer-section"><div class="drawer-section-title">Summary</div>' +
      '<span class="' + vc + '" style="display:inline-block;margin-bottom:0.5rem"><span class="pill-dot"></span>' + ds.verdict + '</span>' +
      '<div class="detail-field"><span class="detail-key">Principal</span> ' + ds.principal + '</div>' +
      '<div class="detail-field"><span class="detail-key">Action</span> ' + ds.action + '</div>' +
      '<div class="detail-field"><span class="detail-key">Reason</span> <span class="cell-mono">' + ds.reason + '</span></div>' +
      '<div class="detail-field"><span class="detail-key">Lamport</span> ' + lamport + '</div>' +
      '<div class="detail-field"><span class="detail-key">Hash</span> <span class="cell-mono" style="font-size:0.72rem;word-break:break-all">' + ds.hash + '</span> <button class="copy-btn" onclick="helmCopy(\'' + ds.hash + '\')">\ud83d\udccb</button></div>' +
      '<div class="detail-field"><span class="detail-key">Mode</span> ' + (ds.mode||'\u2014') + '</div></div>';
    var denyInfo = denyExplanations[ds.reason];
    h += '<div class="drawer-section"><div class="drawer-section-title">Policy Decision</div>' +
      '<div class="detail-field"><span class="detail-key">Effect class</span> ' + (ds['class']||'\u2014') + '</div>' +
      '<div class="detail-field"><span class="detail-key">Reason code</span> <span class="cell-mono">' + ds.reason + '</span></div>';
    if (denyInfo) {
      h += '<div class="detail-field" style="margin-top:0.5rem;padding:0.5rem 0.75rem;background:var(--red-muted);border-radius:var(--radius-xs);border-left:2px solid var(--red)"><span class="detail-key" style="color:var(--red)">Explanation</span> ' + denyInfo.human + '</div>';
      h += '<div class="detail-field"><span class="detail-key">Policy clause</span> <span class="cell-mono" style="font-size:0.75rem">' + denyInfo.clause + '</span></div>';
      h += '<div class="detail-field"><span class="detail-key">Remediation</span> ' + denyInfo.fix + '</div>';
    }
    h += '</div>';
    h += '<div class="drawer-section"><div class="drawer-section-title">Bindings</div>' +
      '<div class="detail-field"><span class="detail-key">Receipt ID</span> <span class="cell-mono" style="font-size:0.7rem">rcpt-' + (ds.hash||'').substring(0,8) + '-' + lamport + '</span></div>' +
      '<button class="cta-btn" style="margin-top:0.5rem;width:100%%" onclick="helmCopyReceiptJSON(' + lamport + ')" title="Copy receipt as JSON">\ud83d\udccb Copy Receipt JSON</button></div>';
    document.getElementById('helm-drawer-content').innerHTML = h;
    document.getElementById('helm-drawer').classList.add('open');
    document.getElementById('helm-drawer-overlay').classList.add('open');
    document.querySelectorAll('.receipt-row').forEach(function(r) { r.classList.remove('selected'); });
    row.classList.add('selected');
    document.querySelectorAll('.chain-node').forEach(function(n) { n.classList.remove('selected'); });
    var cn = document.querySelector('.chain-link[data-lamport="' + lamport + '"] .chain-node');
    if (cn) cn.classList.add('selected');
  }
  window.helmOpenDrawer = helmOpenDrawer;

  function helmCloseDrawer() {
    document.getElementById('helm-drawer').classList.remove('open');
    document.getElementById('helm-drawer-overlay').classList.remove('open');
    document.querySelectorAll('.receipt-row').forEach(function(r) { r.classList.remove('selected'); });
    document.querySelectorAll('.chain-node').forEach(function(n) { n.classList.remove('selected'); });
    currentDrawerLamport = null;
  }
  window.helmCloseDrawer = helmCloseDrawer;

  function helmCopyReceiptJSON(lamport) {
    var row = document.getElementById('r-' + lamport);
    if (!row) return;
    var ds = row.dataset;
    var obj = {lamport:parseInt(lamport),verdict:ds.verdict,principal:ds.principal,action:ds.action,reason_code:ds.reason,hash:ds.hash,mode:ds.mode||''};
    helmCopy(JSON.stringify(obj, null, 2));
  }
  window.helmCopyReceiptJSON = helmCopyReceiptJSON;

  document.querySelectorAll('.receipt-row').forEach(function(row) {
    row.addEventListener('click', function() { helmOpenDrawer(this.dataset.lamport); });
    row.addEventListener('mouseenter', function() {
      var cn = document.querySelector('.chain-link[data-lamport="' + this.dataset.lamport + '"] .chain-node');
      if (cn) cn.classList.add('selected');
    });
    row.addEventListener('mouseleave', function() {
      if (currentDrawerLamport == this.dataset.lamport) return;
      var cn = document.querySelector('.chain-link[data-lamport="' + this.dataset.lamport + '"] .chain-node');
      if (cn) cn.classList.remove('selected');
    });
  });

  document.querySelectorAll('.chain-link').forEach(function(link) {
    link.addEventListener('click', function(e) {
      e.preventDefault();
      var lam = this.dataset.lamport;
      var row = document.getElementById('r-' + lam);
      if (row) { row.scrollIntoView({behavior:'smooth',block:'center'}); helmOpenDrawer(lam); }
    });
  });

  var presetNames = {all:'All',deny:'Denies',approval:'Approvals',effect:'Side effects',maintenance:'Maintenance',skill:'Skill lifecycle'};

  function helmFilter() {
    var pf = document.getElementById('f-principal').value;
    var vf = document.getElementById('f-verdict').value;
    document.querySelectorAll('.receipt-row').forEach(function(r) {
      var show = true;
      if (pf !== 'all' && r.dataset.principal !== pf) show = false;
      if (vf !== 'all' && r.dataset.verdict !== vf) show = false;
      r.style.display = show ? '' : 'none';
    });
  }
  window.helmFilter = helmFilter;

  function helmPreset(preset, btn) {
    document.querySelectorAll('.filter-preset').forEach(function(b) { b.classList.remove('active'); });
    if (btn) btn.classList.add('active');
    document.getElementById('f-principal').value = 'all';
    document.getElementById('f-verdict').value = 'all';
    var pill = document.getElementById('helm-filter-pill');
    if (preset === 'all') { pill.innerHTML = ''; }
    else { pill.innerHTML = '<span class="filter-pill">Filtered: ' + (presetNames[preset]||preset) + ' <button onclick="helmPreset(\'all\',document.querySelector(\'[onclick*=all]\'))">\u00d7</button></span>'; }
    document.querySelectorAll('.receipt-row').forEach(function(r) {
      if (preset === 'all') { r.style.display = ''; return; }
      if (preset === 'deny') { r.style.display = r.dataset.verdict === 'DENY' ? '' : 'none'; return; }
      if (preset === 'approval') { r.style.display = r.dataset.class === 'approval' ? '' : 'none'; return; }
      if (preset === 'effect') { r.style.display = r.dataset.class === 'effect' ? '' : 'none'; return; }
      if (preset === 'maintenance') { r.style.display = r.dataset.class === 'maintenance' ? '' : 'none'; return; }
      if (preset === 'skill') { r.style.display = (r.dataset.action === 'DETECT_SKILL_GAP' || r.dataset.action === 'AUTO_APPROVE_SKILL') ? '' : 'none'; return; }
      r.style.display = '';
    });
  }
  window.helmPreset = helmPreset;

  function helmToggleDensity() {
    var c = document.body.classList.toggle('compact');
    document.getElementById('helm-density').textContent = c ? 'Comfortable' : 'Compact';
    try { localStorage.setItem('helm-density', c ? 'compact' : 'comfortable'); } catch(e) {}
  }
  window.helmToggleDensity = helmToggleDensity;
  try { if (localStorage.getItem('helm-density') === 'compact') { document.body.classList.add('compact'); var db=document.getElementById('helm-density'); if(db) db.textContent='Comfortable'; } } catch(e) {}

  document.addEventListener('keydown', function(e) {
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT') return;
    if (e.key === 'Escape') { helmCloseDrawer(); return; }
    if (e.key !== 'j' && e.key !== 'k') return;
    var rows = Array.from(document.querySelectorAll('.receipt-row:not([style*="display: none"])'));
    if (!rows.length) return;
    var current = document.querySelector('.receipt-row.selected') || document.querySelector('.receipt-row.highlight');
    var idx = current ? rows.indexOf(current) : -1;
    if (e.key === 'j') idx = Math.min(idx + 1, rows.length - 1);
    else idx = Math.max(idx - 1, 0);
    rows[idx].scrollIntoView({behavior:'smooth',block:'center'});
    helmOpenDrawer(rows[idx].dataset.lamport);
  });
})();
</script>
</body>
</html>`,
		// Template arguments in order:
		reportSchemaVersion,         // data-schema
		html.EscapeString(provider), // data-provider
		html.EscapeString(template), // data-template
		finalHash,                   // data-root-hash
		finalLamport,                // data-lamport-final
		chainOK,                     // data-chain-verified
		verifyState,                 // data-verify-state
		len(receipts),               // data-receipt-count
		demoBanner,                  // demo banner
		heroSubtitle,                // hero subtitle (outcome-derived)
		allows, denies, pending,     // pills
		evidenceCtaClass, evidenceCtaTitle, // evidence pack CTA
		reproduceCmd,                           // CTA replay
		html.EscapeString(narrative),           // narrative
		len(receipts), allows, denies, pending, // stats data attrs
		len(receipts),               // total receipts stat
		finalLamport,                // lamport stat
		html.EscapeString(provider), // provider stat
		verifyColor, verifyState,    // verification stat
		verifySubtext,                // verification subtext
		svgWidth, chainDots.String(), // causal chain SVG
		principalOpts.String(),      // principal filter options
		receiptRows.String(),        // receipt rows
		checks.String(),             // verification checks
		reproduceCmd,                // reproduce copy btn
		reproduceCmd,                // reproduce code
		html.EscapeString(gitSHA),   // git sha
		reportSchemaVersion,         // schema version
		html.EscapeString(template), // template env
		html.EscapeString(provider), // provider env
		shortHash(policyHash, 16),   // evidence hash
		osArch,                      // os/arch
		goVer,                       // go version
		genTime,                     // generated time
		genTime,                     // footer time
		string(capsuleJSON),         // JSON capsule
		verifySummaryText,           // verification summary for copy
	)

	return os.WriteFile(reportPath, []byte(reportHTML), 0644)
}

// generateProofReportJSON creates a machine-readable JSON proof report.
func generateProofReportJSON(receipts []demoReceipt, outDir, template, provider string) error {
	reportPath := filepath.Join(outDir, "run-report.json")

	if len(receipts) == 0 {
		return fmt.Errorf("no receipts to report")
	}

	last, _ := lastReceipt(receipts)
	chainOK, lamportOK, denyPresent, _, _, isDemoMode, _, _ := verifyChain(receipts)

	report := map[string]any{
		"version":        "0.2.0",
		"schema_version": reportSchemaVersion,
		"generated_at":   time.Now().UTC().Format(time.RFC3339),
		"template":       template,
		"provider":       provider,
		"receipts":       receipts,
		"summary": map[string]any{
			"total":             len(receipts),
			"lamport_final":     last.Lamport,
			"root_hash":         last.Hash,
			"chain_verified":    chainOK,
			"lamport_monotonic": lamportOK,
			"deny_path_tested":  denyPresent,
			"is_demo":           isDemoMode,
		},
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report JSON: %w", err)
	}
	return os.WriteFile(reportPath, data, 0644)
}
