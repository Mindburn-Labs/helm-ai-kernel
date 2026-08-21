package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	cliui "github.com/Mindburn-Labs/helm-ai-kernel/core/internal/cli/ui"
)

const policyExportSchema = "helm-ai-kernel.policy-export.v1"

type policyExportRecord struct {
	Name           string   `json:"name"`
	Description    string   `json:"description,omitempty"`
	DefaultVerdict string   `json:"default_verdict"`
	AllowedTools   []string `json:"allowed_tools"`
	AllowedEffects []string `json:"allowed_effects"`
	Source         string   `json:"source"`
}

type policyExportReport struct {
	Schema        string               `json:"schema"`
	Dialect       string               `json:"dialect"`
	SourceOfTruth bool                 `json:"source_of_truth"`
	Authoritative string               `json:"authoritative"`
	Limits        []string             `json:"limits"`
	Records       []policyExportRecord `json:"records"`
	Document      string               `json:"document"`
}

var policyExportLimits = []string{
	"This is a read-only view of CLI-visible policy records.",
	"HELM policy remains authoritative; this dialect is not a dual-write target.",
	"Kernel PDP, Cedar/IdP interchange, and live store mapping are not included.",
}

func runPolicyExport(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("policy export", flag.ContinueOnError)
	var (
		dialect string
		file    string
		dir     string
		jsonOut bool
	)
	cmd.StringVar(&dialect, "dialect", "", "View dialect: cedar|opa")
	cmd.StringVar(&file, "file", "", "CLI-visible policy record (JSON template or serve .toml)")
	cmd.StringVar(&dir, "dir", "", "Directory of CLI-visible policy records")
	cmd.BoolVar(&jsonOut, "json", false, "Print JSON (alias for --format=json)")
	formatFlag := cliui.RegisterFormat(cmd, cliui.FormatText)
	if code, ok := cliui.ParseFlags(cmd, args, stderr, "policy export", cliui.FormatText); !ok {
		return code
	}
	jsonOut = jsonOut || formatFlag.IsJSON()
	errFormat := cliui.FormatText
	if jsonOut {
		errFormat = cliui.FormatJSON
	}
	dialect = strings.ToLower(strings.TrimSpace(dialect))
	if dialect != "cedar" && dialect != "opa" {
		return cliui.WriteErrorFormat(stderr, cliui.UsageErrorf("policy export", "--dialect must be cedar or opa").
			WithHint("this is a view, not source of truth"), errFormat)
	}
	if cmd.NArg() > 0 {
		return cliui.WriteErrorFormat(stderr, cliui.UsageErrorf("policy export", "unexpected argument: %s", cmd.Arg(0)), errFormat)
	}

	records, err := loadPolicyExportRecords(file, dir)
	if err != nil {
		return cliui.WriteErrorFormat(stderr, cliui.Wrapf(err, cliui.ExitFailure, "policy export", "load policy records"), errFormat)
	}
	document := renderPolicyDialect(dialect, records)
	report := policyExportReport{
		Schema:        policyExportSchema,
		Dialect:       dialect,
		SourceOfTruth: false,
		Authoritative: "helm_policy",
		Limits:        append([]string(nil), policyExportLimits...),
		Records:       records,
		Document:      document,
	}
	if jsonOut {
		if err := cliui.WriteJSON(stdout, report); err != nil {
			return 1
		}
		return 0
	}
	_, _ = fmt.Fprint(stdout, document)
	if !strings.HasSuffix(document, "\n") {
		_, _ = fmt.Fprintln(stdout)
	}
	return 0
}

func loadPolicyExportRecords(file, dir string) ([]policyExportRecord, error) {
	var paths []string
	if file != "" {
		paths = append(paths, file)
	}
	if dir != "" {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			ext := strings.ToLower(filepath.Ext(name))
			if ext == ".json" || ext == ".toml" {
				paths = append(paths, filepath.Join(dir, name))
			}
		}
	}
	if len(paths) == 0 {
		for _, name := range []string{"deny-first", "safe-shell", "safe-file", "safe-web", "safe-deploy"} {
			tmpl := getTemplate(name)
			if tmpl == nil {
				continue
			}
			paths = append(paths, "template:"+name)
		}
	}
	sort.Strings(paths)
	var records []policyExportRecord
	seen := map[string]struct{}{}
	for _, path := range paths {
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		rec, err := loadOnePolicyExportRecord(path)
		if err != nil {
			return nil, err
		}
		records = append(records, rec)
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].Name != records[j].Name {
			return records[i].Name < records[j].Name
		}
		return records[i].Source < records[j].Source
	})
	return records, nil
}

func loadOnePolicyExportRecord(path string) (policyExportRecord, error) {
	if strings.HasPrefix(path, "template:") {
		tmpl := getTemplate(strings.TrimPrefix(path, "template:"))
		if tmpl == nil {
			return policyExportRecord{}, fmt.Errorf("unknown template %s", path)
		}
		return recordFromTemplate(*tmpl, path), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return policyExportRecord{}, err
	}
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".toml" {
		runtime, err := loadServePolicyRuntimeFromBytes(path, data)
		if err != nil {
			return policyExportRecord{}, err
		}
		tools := make([]string, 0, len(runtime.AllowMap()))
		for action := range runtime.AllowMap() {
			tools = append(tools, action)
		}
		sort.Strings(tools)
		name := runtime.Policy.Name
		if name == "" {
			name = filepath.Base(path)
		}
		return policyExportRecord{
			Name:           name,
			Description:    "serve policy view",
			DefaultVerdict: "deny",
			AllowedTools:   tools,
			AllowedEffects: nil,
			Source:         path,
		}, nil
	}
	var tmpl PolicyTemplate
	if err := json.Unmarshal(data, &tmpl); err != nil {
		return policyExportRecord{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return recordFromTemplate(tmpl, path), nil
}

func recordFromTemplate(tmpl PolicyTemplate, source string) policyExportRecord {
	tools := append([]string(nil), tmpl.AllowedTools...)
	effects := append([]string(nil), tmpl.AllowedEffects...)
	sort.Strings(tools)
	sort.Strings(effects)
	verdict := strings.ToLower(strings.TrimSpace(tmpl.DefaultVerdict))
	if verdict == "" {
		verdict = "deny"
	}
	return policyExportRecord{
		Name:           tmpl.Name,
		Description:    tmpl.Description,
		DefaultVerdict: verdict,
		AllowedTools:   tools,
		AllowedEffects: effects,
		Source:         source,
	}
}

func renderPolicyDialect(dialect string, records []policyExportRecord) string {
	if dialect == "opa" {
		return renderOPAView(records)
	}
	return renderCedarView(records)
}

func renderCedarView(records []policyExportRecord) string {
	var b strings.Builder
	b.WriteString("// HELM policy view. Not source of truth. HELM policy remains authoritative.\n")
	b.WriteString("// Dual-write is forbidden. Limits: CLI-visible records only.\n")
	if len(records) == 0 {
		b.WriteString("forbid (principal, action, resource);\n")
		return b.String()
	}
	for _, rec := range records {
		b.WriteString("\n// record: " + rec.Name + " source=" + rec.Source + "\n")
		if rec.DefaultVerdict != "allow" {
			b.WriteString("forbid (\n  principal,\n  action,\n  resource\n);\n")
		}
		for _, tool := range rec.AllowedTools {
			if len(rec.AllowedEffects) == 0 {
				fmt.Fprintf(&b, "permit (\n  principal,\n  action == Action::%q,\n  resource\n);\n", tool)
				continue
			}
			effects := make([]string, 0, len(rec.AllowedEffects))
			for _, effect := range rec.AllowedEffects {
				effects = append(effects, fmt.Sprintf("%q", effect))
			}
			fmt.Fprintf(&b, "permit (\n  principal,\n  action == Action::%q,\n  resource\n) when { context.effect in [%s] };\n",
				tool, strings.Join(effects, ", "))
		}
	}
	return b.String()
}

func renderOPAView(records []policyExportRecord) string {
	var b strings.Builder
	b.WriteString("# HELM policy view. Not source of truth. HELM policy remains authoritative.\n")
	b.WriteString("# Dual-write is forbidden. Limits: CLI-visible records only.\n")
	b.WriteString("package helm.policy.view\n\n")
	b.WriteString("default allow := false\n")
	for _, rec := range records {
		b.WriteString("\n# record: " + rec.Name + " source=" + rec.Source + "\n")
		for _, tool := range rec.AllowedTools {
			if len(rec.AllowedEffects) == 0 {
				fmt.Fprintf(&b, "allow if { input.tool == %q }\n", tool)
				continue
			}
			for _, effect := range rec.AllowedEffects {
				fmt.Fprintf(&b, "allow if { input.tool == %q; input.effect == %q }\n", tool, effect)
			}
		}
	}
	return b.String()
}
