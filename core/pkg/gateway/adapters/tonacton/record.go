package tonacton

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
)

var spendRe = regexp.MustCompile(spendPattern)

func recordPath(tenantRoot, attemptID string) string {
	return filepath.Join(tenantRoot, ".runs", attemptID+".json")
}

// writeRecord stores the record atomically, readable by the gateway only.
func (a *Adapter) writeRecord(tenantRoot, attemptID string, rec runRecord) error {
	body, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	dir := filepath.Join(tenantRoot, ".runs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), recordPath(tenantRoot, attemptID))
}

func decodeRecord(raw []byte) (runRecord, error) {
	var rec runRecord
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rec); err != nil {
		return rec, err
	}
	if rec.Version != recordVersion {
		return rec, errors.New("unknown record version")
	}
	return rec, nil
}

func markerPath(tenantRoot, attemptID string) string {
	return filepath.Join(tenantRoot, ".runs", attemptID+".started")
}

// writeMarker creates the attempt marker exclusively.
func writeMarker(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- built from a validated tenant id and attempt id
	if err != nil {
		return err
	}
	return f.Close()
}

// projectConfigNames are the files Acton loads from the project directory and
// its parents, and that can redirect a wallet or inject environment.
func isProjectConfig(name string) bool {
	return strings.HasPrefix(name, ".env") || name == "wallets.toml" || name == "global.wallets.toml"
}

// refuseProjectConfig refuses a working directory, or any directory above it up
// to the tenant root, that holds a file Acton auto-loads: a tenant could use it
// to set environment variables or point Acton at a wallet file.
func refuseProjectConfig(workspaceRoot, tenantRoot, dir string) *adapters.Refusal {
	for d := dir; ; d = filepath.Dir(d) {
		entries, err := os.ReadDir(d)
		if err != nil {
			return adapters.Refuse(contracts.ReasonProviderError, "the workspace cannot be read")
		}
		for _, e := range entries {
			if isProjectConfig(e.Name()) {
				return adapters.Refuse(contracts.ReasonPreconditionFailed, "the workspace holds %s, which Acton loads on its own; remove it", e.Name())
			}
		}
		if d == tenantRoot || d == workspaceRoot || filepath.Dir(d) == d {
			return nil
		}
	}
}
