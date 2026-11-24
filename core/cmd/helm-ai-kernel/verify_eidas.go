package main

// quantum_posture: This flag check reads timestamp anchor metadata.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier/packfs"
)

// checkEIDASAnchorMetadata inventories anchor records whose metadata declares
// backend == "eidas-qtsp" and checks that integrated_time is parseable and no
// older than maxAge. It does not parse or verify an RFC 3161 token, validate a
// message imprint or signature, consult an EU Trusted List, establish receipt
// coverage, or prove eIDAS/QTSP qualification.
//
// Anchor receipts are looked up under <bundle>/02_PROOFGRAPH/anchors/*.json
// and as embedded shapes inside <bundle>/00_INDEX.json (key "anchor"). The
// receipt JSON shape mirrors anchor.AnchorReceipt: {backend, log_id,
// log_index, integrated_time, signature, request:{...}}.
func checkEIDASAnchorMetadata(bundleRoot string, maxAge time.Duration) []verifier.CheckResult {
	const eidasBackend = "eidas-qtsp"

	results := make([]verifier.CheckResult, 0, 4)

	// Inventory candidate anchors from the pack, read through an os.Root on
	// its directory: a link out of the pack or a named pipe is refused.
	pack, packErr := packfs.Open(bundleRoot)
	if packErr != nil {
		return append(results, verifier.CheckResult{
			Name:   "eidas:read_anchor",
			Pass:   false,
			Reason: fmt.Sprintf("cannot open the pack: %v", packErr),
		})
	}
	defer func() { _ = pack.Close() }()
	const anchorsName = "02_PROOFGRAPH/anchors"
	anchorsDir := filepath.Join(bundleRoot, "02_PROOFGRAPH", "anchors")
	entries, err := pack.ReadDir(anchorsName)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		results = append(results, verifier.CheckResult{
			Name:   "eidas:read_anchor",
			Pass:   false,
			Reason: fmt.Sprintf("cannot read %s: %v", anchorsName, err),
		})
	}

	type anchorMeta struct {
		Path           string
		Backend        string
		IntegratedRaw  string
		IntegratedTime time.Time
	}
	var anchors []anchorMeta

	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".json") {
			continue
		}
		path := filepath.Join(anchorsDir, ent.Name())
		data, err := pack.ReadFile(anchorsName + "/" + ent.Name())
		if err != nil {
			results = append(results, verifier.CheckResult{
				Name:   "eidas:read_anchor",
				Pass:   false,
				Reason: fmt.Sprintf("cannot read %s: %v", path, err),
			})
			continue
		}
		var doc map[string]any
		if err := json.Unmarshal(data, &doc); err != nil {
			results = append(results, verifier.CheckResult{
				Name:   "eidas:parse_anchor",
				Pass:   false,
				Reason: fmt.Sprintf("cannot parse %s: %v", path, err),
			})
			continue
		}
		backend, _ := doc["backend"].(string)
		ts, _ := doc["integrated_time"].(string)
		parsed, _ := time.Parse(time.RFC3339, ts)
		anchors = append(anchors, anchorMeta{Path: path, Backend: backend, IntegratedRaw: ts, IntegratedTime: parsed})
	}

	// Also check 00_INDEX.json's embedded anchor field, when present.
	if data, err := pack.ReadFile("00_INDEX.json"); err != nil && !errors.Is(err, fs.ErrNotExist) {
		results = append(results, verifier.CheckResult{
			Name:   "eidas:read_anchor",
			Pass:   false,
			Reason: fmt.Sprintf("cannot read 00_INDEX.json: %v", err),
		})
	} else if err == nil {
		var doc map[string]any
		if json.Unmarshal(data, &doc) == nil {
			if a, ok := doc["anchor"].(map[string]any); ok {
				backend, _ := a["backend"].(string)
				ts, _ := a["integrated_time"].(string)
				parsed, _ := time.Parse(time.RFC3339, ts)
				anchors = append(anchors, anchorMeta{Path: "00_INDEX.json#anchor", Backend: backend, IntegratedRaw: ts, IntegratedTime: parsed})
			}
		}
	}

	if len(anchors) == 0 {
		results = append(results, verifier.CheckResult{
			Name:   "eidas:require",
			Pass:   false,
			Reason: "no anchor metadata found under 02_PROOFGRAPH/anchors/ or 00_INDEX.json#anchor; --require-eidas needs at least one record declaring backend=eidas-qtsp and does not establish eIDAS qualification",
		})
		return results
	}

	now := time.Now().UTC()
	hasEIDAS := false
	for _, a := range anchors {
		if a.Backend != eidasBackend {
			results = append(results, verifier.CheckResult{
				Name:   "eidas:anchor_backend",
				Pass:   false,
				Reason: fmt.Sprintf("anchor %s has backend %q, not %q", a.Path, a.Backend, eidasBackend),
			})
			continue
		}
		hasEIDAS = true
		if strings.TrimSpace(a.IntegratedRaw) == "" || a.IntegratedTime.IsZero() {
			results = append(results, verifier.CheckResult{
				Name:   "eidas:anchor_metadata",
				Pass:   false,
				Reason: fmt.Sprintf("anchor %s must declare integrated_time as RFC3339 metadata; no timestamp token or EU Trusted List verification was performed", a.Path),
			})
			continue
		}
		if maxAge > 0 && now.Sub(a.IntegratedTime) > maxAge {
			results = append(results, verifier.CheckResult{
				Name: "eidas:anchor_freshness",
				Pass: false,
				Reason: fmt.Sprintf("anchor %s integrated_time %s is older than --eidas-max-age-hours window of %s",
					a.Path, a.IntegratedTime.Format(time.RFC3339), maxAge),
			})
			continue
		}
		results = append(results, verifier.CheckResult{
			Name:   "eidas:anchor_metadata",
			Pass:   true,
			Detail: fmt.Sprintf("%s declares backend=%s and integrated_time=%s; metadata only, RFC 3161 token and EU Trusted List were not verified", a.Path, eidasBackend, a.IntegratedTime.Format(time.RFC3339)),
		})
	}

	if !hasEIDAS {
		results = append(results, verifier.CheckResult{
			Name:   "eidas:require",
			Pass:   false,
			Reason: "no anchor with backend=eidas-qtsp found",
		})
	}

	return results
}
