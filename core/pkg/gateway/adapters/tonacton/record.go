package tonacton

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

var spendRe = regexp.MustCompile(spendPattern)

func effectargsMainnet(effectType string) bool { return effectargs.IsTONActonMainnet(effectType) }

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
