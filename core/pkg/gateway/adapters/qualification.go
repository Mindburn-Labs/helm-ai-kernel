package adapters

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// Qualification is executable (§9.3): a versioned suite per adapter version
// and operation, run against a provider environment. The record says what
// ran and where. There is no badge beyond it, and a check that did not run
// is never a pass (rev 3.4 R2).

// SuiteCase is one qualification check.
type SuiteCase struct {
	ID        string `json:"id"`
	Operation string `json:"operation"`
	// Category is the §9.3 failure case it covers, or "boundary" for the
	// target and argument checks the audit added (09-02).
	Category    string `json:"category"`
	Description string `json:"description"`
}

// Suite is an adapter's qualification suite.
type Suite struct {
	Adapter        string      `json:"adapter"`
	AdapterVersion string      `json:"adapter_version"`
	SuiteVersion   string      `json:"suite_version"`
	Cases          []SuiteCase `json:"cases"`
}

// Digest is SHA-256, in hex, over the suite's JSON encoding: the adapter
// version, the suite version and every case in order.
func (s Suite) Digest() string {
	raw, err := json.Marshal(s)
	if err != nil {
		panic(err) // plain strings only; cannot fail
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// CheckStatus is one check's result.
type CheckStatus string

const (
	CheckPass    CheckStatus = "PASS"
	CheckFail    CheckStatus = "FAIL"
	CheckSkipped CheckStatus = "SKIPPED"
)

// CheckResult is one executed (or skipped) case.
type CheckResult struct {
	ID     string      `json:"id"`
	Status CheckStatus `json:"status"`
}

// QualificationRecord is the §9.3 record for one adapter version, operation
// and environment.
type QualificationRecord struct {
	Adapter        string        `json:"adapter"`
	AdapterVersion string        `json:"adapter_version"`
	Operation      string        `json:"operation"`
	Environment    string        `json:"environment"`
	SuiteVersion   string        `json:"suite_version"`
	SuiteDigest    string        `json:"suite_digest"`
	Checks         []CheckResult `json:"checks"`
	Limitations    []string      `json:"limitations,omitempty"`
	// Qualified is true only when every case of the operation ran and passed.
	Qualified bool `json:"qualified"`
}

// Records builds one record per operation of the suite from the results.
// A case with no result counts as SKIPPED, so an operation qualifies only if
// every one of its cases is present and PASS.
func (s Suite) Records(environment string, results map[string]CheckStatus, limitations []string) []QualificationRecord {
	var out []QualificationRecord
	index := map[string]int{}
	for _, c := range s.Cases {
		i, ok := index[c.Operation]
		if !ok {
			i = len(out)
			index[c.Operation] = i
			out = append(out, QualificationRecord{
				Adapter:        s.Adapter,
				AdapterVersion: s.AdapterVersion,
				Operation:      c.Operation,
				Environment:    environment,
				SuiteVersion:   s.SuiteVersion,
				SuiteDigest:    s.Digest(),
				Limitations:    limitations,
				Qualified:      true,
			})
		}
		status, ran := results[c.ID]
		if !ran {
			status = CheckSkipped
		}
		out[i].Checks = append(out[i].Checks, CheckResult{ID: c.ID, Status: status})
		if status != CheckPass {
			out[i].Qualified = false
		}
	}
	return out
}
