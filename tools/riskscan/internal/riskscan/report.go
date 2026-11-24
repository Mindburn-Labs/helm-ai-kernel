package riskscan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"sort"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/tools/riskscan/internal/riskenvelope"
)

func EnvelopeJSON(envelope riskenvelope.RiskEnvelope) ([]byte, error) {
	if err := envelope.Validate(); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func RenderMarkdown(envelope riskenvelope.RiskEnvelope) ([]byte, error) {
	if err := envelope.Validate(); err != nil {
		return nil, err
	}
	view := newPreviewView(envelope)
	var b strings.Builder
	fmt.Fprintf(&b, "# HELM AI Agent Risk Surface\n\n")
	if view.BoundaryGrade != "" {
		fmt.Fprintf(&b, "## Boundary grade: %s\n\n", view.BoundaryGrade)
		fmt.Fprintf(&b, "%s\n\n", view.BoundaryGradeReason)
		fmt.Fprintf(&b, "The grade covers declared and locally discoverable configuration. It does not establish what an agent executed at runtime.\n\n")
	}
	fmt.Fprintf(&b, "- Envelope: `%s`\n", view.EnvelopeID)
	fmt.Fprintf(&b, "- Content hash: `%s`\n", view.ContentHash)
	fmt.Fprintf(&b, "- Generated: `%s`\n", view.GeneratedAt)
	fmt.Fprintf(&b, "- Agent surface: `%s`\n", view.AgentSurface)
	fmt.Fprintf(&b, "- Permission mode: `%s`\n", view.PermissionMode)
	fmt.Fprintf(&b, "- MCP servers detected: `%d`\n", view.MCPServerCount)
	fmt.Fprintf(&b, "- Static config files read: `%d`\n\n", view.StaticConfigFilesRead)
	fmt.Fprintf(&b, "## Findings\n\n")
	if len(view.FindingsBySeverity) == 0 {
		fmt.Fprintf(&b, "No upload-safe findings detected.\n\n")
	} else {
		for _, row := range view.FindingsBySeverity {
			fmt.Fprintf(&b, "- `%s`: %d\n", row.Name, row.Count)
		}
		fmt.Fprintf(&b, "\n")
	}
	fmt.Fprintf(&b, "## Risk Codes\n\n")
	for _, row := range view.FindingsByRisk {
		fmt.Fprintf(&b, "- `%s`: %d\n", row.Name, row.Count)
	}
	if len(view.FindingsByRisk) == 0 {
		fmt.Fprintf(&b, "No risk codes emitted.\n")
	}
	fmt.Fprintf(&b, "\n## Privacy\n\n")
	fmt.Fprintf(&b, "This preview is generated from the anonymized RiskEnvelope only. Raw prompts, source code, secret values, command bodies, raw paths, and raw repository names are not present.\n")
	return []byte(b.String()), nil
}

func RenderHTML(envelope riskenvelope.RiskEnvelope) ([]byte, error) {
	if err := envelope.Validate(); err != nil {
		return nil, err
	}
	tpl := template.Must(template.New("risk-preview").Parse(htmlPreviewTemplate))
	var b bytes.Buffer
	if err := tpl.Execute(&b, newPreviewView(envelope)); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

type previewRow struct {
	Name  string
	Count int
}

type previewView struct {
	EnvelopeID            string
	ContentHash           string
	BoundaryGrade         string
	BoundaryGradeReason   string
	GeneratedAt           string
	AgentSurface          string
	PermissionMode        string
	MCPServerCount        int
	StaticConfigFilesRead int
	FindingsBySeverity    []previewRow
	FindingsByRisk        []previewRow
}

func newPreviewView(envelope riskenvelope.RiskEnvelope) previewView {
	severity := map[string]int{}
	risk := map[string]int{}
	for _, finding := range envelope.Findings {
		severity[string(finding.Severity)]++
		risk[string(finding.RiskCode)]++
	}
	grade, gradeReason := "", ""
	if envelope.BoundaryGrade != nil {
		grade = string(envelope.BoundaryGrade.Letter)
		gradeReason = string(envelope.BoundaryGrade.Reason)
	}
	return previewView{
		EnvelopeID:            envelope.EnvelopeID,
		ContentHash:           envelope.EnvelopeContentHash,
		BoundaryGrade:         grade,
		BoundaryGradeReason:   gradeReason,
		GeneratedAt:           envelope.GeneratedAt.UTC().Format(time.RFC3339),
		AgentSurface:          string(envelope.Posture.AgentSurface),
		PermissionMode:        string(envelope.Posture.PermissionMode),
		MCPServerCount:        envelope.Posture.MCPServerCount,
		StaticConfigFilesRead: envelope.Posture.StaticConfigFilesRead,
		FindingsBySeverity:    sortedRows(severity),
		FindingsByRisk:        sortedRows(risk),
	}
}

func sortedRows(counts map[string]int) []previewRow {
	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	sort.Strings(names)
	rows := make([]previewRow, 0, len(names))
	for _, name := range names {
		rows = append(rows, previewRow{Name: name, Count: counts[name]})
	}
	return rows
}

const htmlPreviewTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>HELM AI Agent Risk Surface</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 32px; color: #17202a; }
    main { max-width: 880px; }
    code { background: #f2f4f7; padding: 2px 5px; border-radius: 4px; }
    table { border-collapse: collapse; width: 100%; margin: 16px 0 28px; }
    th, td { border-bottom: 1px solid #d8dee8; padding: 8px 4px; text-align: left; }
    th { font-size: 12px; text-transform: uppercase; letter-spacing: .04em; color: #52606d; }
    .grade { font-size: 28px; font-weight: 600; margin: 0 0 4px; }
    .grade-reason { margin: 0 0 4px; }
    .grade-scope { color: #52606d; font-size: 13px; margin: 0 0 24px; }
  </style>
</head>
<body>
<main>
  <h1>HELM AI Agent Risk Surface</h1>
  {{if .BoundaryGrade}}<p class="grade">Boundary grade: {{.BoundaryGrade}}</p>
  <p class="grade-reason">{{.BoundaryGradeReason}}</p>
  <p class="grade-scope">The grade covers declared and locally discoverable configuration. It does not establish what an agent executed at runtime.</p>{{end}}
  <p>Envelope <code>{{.EnvelopeID}}</code></p>
  <p>Content hash <code>{{.ContentHash}}</code></p>
  <table>
    <tr><th>Generated</th><td>{{.GeneratedAt}}</td></tr>
    <tr><th>Agent surface</th><td>{{.AgentSurface}}</td></tr>
    <tr><th>Permission mode</th><td>{{.PermissionMode}}</td></tr>
    <tr><th>MCP servers</th><td>{{.MCPServerCount}}</td></tr>
    <tr><th>Static config files read</th><td>{{.StaticConfigFilesRead}}</td></tr>
  </table>
  <h2>Findings By Severity</h2>
  <table><tr><th>Severity</th><th>Count</th></tr>{{range .FindingsBySeverity}}<tr><td>{{.Name}}</td><td>{{.Count}}</td></tr>{{else}}<tr><td colspan="2">No upload-safe findings detected.</td></tr>{{end}}</table>
  <h2>Risk Codes</h2>
  <table><tr><th>Risk code</th><th>Count</th></tr>{{range .FindingsByRisk}}<tr><td>{{.Name}}</td><td>{{.Count}}</td></tr>{{else}}<tr><td colspan="2">No risk codes emitted.</td></tr>{{end}}</table>
  <h2>Privacy</h2>
  <p>This preview is generated from the anonymized RiskEnvelope only. Raw prompts, source code, secret values, command bodies, raw paths, and raw repository names are not present.</p>
</main>
</body>
</html>
`
