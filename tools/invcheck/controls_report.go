package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

type coverageMap struct {
	GeneratedFrom string          `json:"generated_from"`
	Rule          string          `json:"rule"`
	Annotations   []string        `json:"annotations"`
	Summary       coverageSummary `json:"summary"`
	Controls      []coverageEntry `json:"controls"`
}

type coverageSummary struct {
	Total        int `json:"total"`
	Enforced     int `json:"enforced"`
	ObservedOnly int `json:"observed_only"`
	Unmanaged    int `json:"unmanaged"`
	Retired      int `json:"retired_invariants"`
	BuildPlane   int `json:"build_plane"`
}

type coverageEntry struct {
	ID                  string            `json:"id"`
	Title               string            `json:"title"`
	Owner               string            `json:"owner"`
	Claim               string            `json:"claim"`
	Status              string            `json:"status"`
	Plane               string            `json:"plane"`
	Reason              string            `json:"reason,omitempty"`
	Retired             bool              `json:"retired,omitempty"`
	EntryPoints         []entryPointState `json:"entry_points"`
	Gates               []string          `json:"gates"`
	Config              []string          `json:"config"`
	ProtectedOperations []string          `json:"protected_operations"`
	BypassAssumptions   []string          `json:"bypass_assumptions"`
	Tests               testSet           `json:"tests"`
	RemovalProofs       []proofSummary    `json:"removal_proofs"`
}

type entryPointState struct {
	Symbol       string `json:"symbol"`
	Reachability string `json:"reachability"`
}

type proofSummary struct {
	File  string   `json:"file"`
	Tests []string `json:"tests"`
}

func summarizeStatus(reg *registry) coverageSummary {
	var s coverageSummary
	for _, c := range reg.Controls {
		s.Total++
		switch c.Status {
		case statusEnforced:
			s.Enforced++
		case statusObservedOnly:
			s.ObservedOnly++
		case statusUnmanaged:
			s.Unmanaged++
		}
		if c.Retired {
			s.Retired++
		}
		if c.plane() == planeBuild {
			s.BuildPlane++
		}
	}
	return s
}

func generateCoverageMap(reg *registry, ev *evidence) []byte {
	cm := coverageMap{
		GeneratedFrom: registryFile + " via make controls; do not edit by hand",
		Rule: "R1: an entry is enforced only on its tested path: reachable from a shipped binary, " +
			"its tests passing, and its removal tests failing once the control is deleted",
		Annotations: []string{"quantum_posture: this map records which code paths hold existing signing, " +
			"hashing and key-separation properties; it pins no algorithm and makes no post-quantum claim"},
		Summary:  summarizeStatus(reg),
		Controls: []coverageEntry{},
	}
	for _, c := range reg.Controls {
		e := coverageEntry{
			ID: c.ID, Title: c.Title, Owner: c.Owner, Claim: strings.TrimSpace(c.Claim), Status: c.Status,
			Plane: c.plane(), Reason: strings.TrimSpace(c.Reason), Retired: c.Retired,
			EntryPoints: []entryPointState{}, Gates: nonNil(c.Gates), Config: nonNil(c.Config),
			ProtectedOperations: nonNil(c.ProtectedOperations), BypassAssumptions: nonNil(c.BypassAssumptions),
			Tests: testSet{
				Allowed: nonNil(c.Tests.Allowed), Forbidden: nonNil(c.Tests.Forbidden),
				Removal: nonNil(c.Tests.Removal), Bypass: nonNil(c.Tests.Bypass),
			},
			RemovalProofs: []proofSummary{},
		}
		for _, s := range c.EntryPoints {
			state := missing
			if r, ok := parseRef(s); ok {
				state = ev.reachability(r)
			}
			e.EntryPoints = append(e.EntryPoints, entryPointState{Symbol: s, Reachability: state})
		}
		for _, rp := range reg.RemovalProofs {
			if rp.Control == c.ID {
				e.RemovalProofs = append(e.RemovalProofs, proofSummary{File: rp.File, Tests: nonNil(rp.Tests)})
			}
		}
		cm.Controls = append(cm.Controls, e)
	}
	out, _ := json.MarshalIndent(cm, "", "  ")
	return append(out, '\n')
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// generateInvariants renders HELM_INVARIANTS.md. The invariant blocks keep the
// exact shape invcheck verify and concept-gate parse.
func generateInvariants(reg *registry) []byte {
	var b strings.Builder
	d := reg.Document
	fmt.Fprintf(&b, "---\ntitle: %s\nlast_reviewed: %s\n---\n\n# %s\n\n", d.Title, d.LastReviewed, d.Title)
	b.WriteString(ensureNewline(d.Preamble))
	b.WriteString("\n---\n\n## Enforcement status\n\n")
	b.WriteString(statusTable(reg))
	for _, s := range reg.Sections {
		fmt.Fprintf(&b, "\n---\n\n## %s\n", s.Title)
		if s.Intro != "" {
			b.WriteString("\n" + ensureNewline(s.Intro))
		}
		for _, c := range reg.Controls {
			if c.Section != s.ID || !strings.HasPrefix(c.ID, "INV-") {
				continue
			}
			fmt.Fprintf(&b, "\n### %s — %s\n\n%s\n", c.ID, c.Title, ensureNewline(c.Body))
			for _, v := range c.Verify {
				fmt.Fprintf(&b, "verify: %s\n", v)
			}
		}
	}
	return []byte(b.String())
}

func statusTable(reg *registry) string {
	s := summarizeStatus(reg)
	var b strings.Builder
	b.WriteString("Generated from [`controls.yaml`](controls.yaml) by `make controls`; do not edit\n")
	b.WriteString("this section or the invariant text below by hand. `make controls-check` fails\n")
	b.WriteString("when this file or `coverage-map.json` differs from the registry. A runtime\n")
	b.WriteString("entry is `enforced` only when every entry point is reachable from a shipped\n")
	b.WriteString("binary (`scripts/ci/deadcode-roots.txt`), its allowed, forbidden and removal\n")
	b.WriteString("tests run and pass, and deleting the control makes its removal tests fail. A\n")
	b.WriteString("`build` entry is held by CI gates that block pull requests. Everything else\n")
	b.WriteString("is `observed-only` or `unmanaged`, with the reason.\n\n")
	fmt.Fprintf(&b, "%d controls: %d enforced (%d of them by CI gates), %d observed-only, %d unmanaged (%d of them retired invariants).\n\n",
		s.Total, s.Enforced, s.BuildPlane, s.ObservedOnly, s.Unmanaged, s.Retired)
	b.WriteString("| Id | Control | Status | Why it is not enforced |\n| --- | --- | --- | --- |\n")
	for _, c := range reg.Controls {
		status := c.Status
		switch {
		case c.Retired:
			status = "retired"
		case c.plane() == planeBuild:
			status += " (build)"
		}
		reason := cell(c.Reason)
		if reason == "" {
			reason = "—"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", c.ID, cell(c.Title), status, reason)
	}
	return b.String()
}

func cell(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	return strings.ReplaceAll(s, "|", `\|`)
}

func ensureNewline(s string) string {
	if strings.HasSuffix(s, "\n") {
		return s
	}
	return s + "\n"
}

func driftProblem(name string, committed, generated []byte) *issue {
	if bytes.Equal(committed, generated) {
		return nil
	}
	return &issue{Kind: "stale-generated", ID: name, Msg: name + " differs from what " + registryFile + " generates; run `make controls`"}
}
