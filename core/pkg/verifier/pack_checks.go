package verifier

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier/packfs"
)

// --- Check implementations ---

func checkStructure(bundlePath string) CheckResult {
	info, err := os.Stat(bundlePath)
	if err != nil {
		return CheckResult{Name: "structure", Pass: false, Reason: fmt.Sprintf("path not found: %v", err)}
	}
	if !info.IsDir() {
		return CheckResult{Name: "structure", Pass: false, Reason: "bundle must be a directory (tar.gz extraction not yet supported in library)"}
	}

	// Check for manifest.json or 00_INDEX.json
	pack := openPack(bundlePath)
	defer pack.close()
	hasManifest, err := pack.hasFile("manifest.json")
	if err != nil {
		return failed("structure", fmt.Sprintf("manifest.json is not read: %v", err))
	}
	hasIndex, err := pack.hasFile("00_INDEX.json")
	if err != nil {
		return failed("structure", fmt.Sprintf("00_INDEX.json is not read: %v", err))
	}

	if !hasManifest && !hasIndex {
		return CheckResult{Name: "structure", Pass: false, Reason: "missing manifest.json or 00_INDEX.json"}
	}

	// Only the presence of an index or manifest file is established here; what
	// they list is checked by index_integrity, file_hashes and the seal.
	present := "00_INDEX.json"
	switch {
	case hasManifest && hasIndex:
		present = "00_INDEX.json and manifest.json"
	case hasManifest:
		present = "manifest.json"
	}
	return verified("structure", "pack is a directory that holds "+present)
}

func checkIndex(bundlePath string) CheckResult {
	const name = "index_integrity"
	pack := openPack(bundlePath)
	defer pack.close()
	hasIndex, err := pack.hasFile("00_INDEX.json")
	if err != nil {
		return failed(name, fmt.Sprintf("cannot read index: %v", err))
	}
	if !hasIndex {
		// A manifest.json pack lists its hashes in the manifest; file_hashes
		// reads those. Parsing the manifest here used to count as index
		// integrity although no index was compared.
		return notRun(name, "pack has no 00_INDEX.json, so there are no indexed hashes to compare")
	}

	data, err := pack.readFile("00_INDEX.json")
	if err != nil {
		return failed(name, fmt.Sprintf("cannot read index: %v", err))
	}
	var index indexFile
	if err := json.Unmarshal(data, &index); err != nil {
		return failed(name, fmt.Sprintf("invalid index JSON: %v", err))
	}
	if len(index.Entries) == 0 {
		return notRun(name, "00_INDEX.json lists no entries, so there are no indexed hashes to compare")
	}
	for _, entry := range index.Entries {
		if entry.Path == "" {
			return failed(name, "index entry path is required")
		}
		actual, err := pack.hashNamed(entry.Path)
		switch {
		case errors.Is(err, packfs.ErrOutside):
			return failed(name, fmt.Sprintf("index entry escapes bundle: %v", err))
		case absent(err):
			return failed(name, fmt.Sprintf("indexed file missing %s: %v", entry.Path, err))
		case err != nil:
			return failed(name, fmt.Sprintf("indexed file %s cannot be read: %v", entry.Path, err))
		}
		if actual != entry.SHA256 {
			return failed(name, fmt.Sprintf("indexed hash mismatch for %s: expected %s, got %s", entry.Path, entry.SHA256, actual))
		}
	}
	return verified(name, fmt.Sprintf("%d files listed in 00_INDEX.json are present and match their SHA-256", len(index.Entries)))
}

// checkRoots derives the manifest root hash and Merkle root from the hashes
// 00_INDEX.json lists. It compares them with nothing: the seal check does that.
// An index that lists no entries leaves it NOT_RUN, as it leaves
// index_integrity.
func checkRoots(bundlePath string, report *VerifyReport) CheckResult {
	const name = "roots"
	pack := openPack(bundlePath)
	hasIndex, err := pack.hasFile("00_INDEX.json")
	pack.close()
	if err != nil {
		return failed(name, fmt.Sprintf("00_INDEX.json is not read: %v", err))
	}
	if !hasIndex {
		return notRun(name, "pack has no 00_INDEX.json to derive roots from")
	}
	roots, err := computeIndexRoots(bundlePath)
	if err != nil {
		return failed(name, err.Error())
	}
	if roots.EntryCount == 0 {
		// The same state index_integrity reports for this index: roots over
		// no entries are derived from nothing, and say nothing about a file.
		return notRun(name, "00_INDEX.json lists no entries, so there are no indexed hashes to derive roots from")
	}
	if roots.ManifestRootHash == "" {
		return failed(name, "00_INDEX.json yielded no manifest root hash")
	}
	report.Roots = roots
	report.MerkleRoot = roots.MerkleRoot
	return verified(name, fmt.Sprintf("derived from 00_INDEX.json: %d indexed entries; manifest_root_hash=%s; merkle_root=%s", roots.EntryCount, roots.ManifestRootHash, roots.MerkleRoot))
}

type indexEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type indexFile struct {
	Entries []indexEntry `json:"entries"`
}

func computeIndexRoots(bundlePath string) (VerifyRoots, error) {
	roots, err := evidencepkg.ComputeEvidencePackIndexRoots(bundlePath)
	if err != nil {
		return VerifyRoots{}, err
	}
	return VerifyRoots{
		ManifestRootHash: roots.IndexHash,
		MerkleRoot:       roots.MerkleRoot,
		EntryCount:       roots.EntryCount,
	}, nil
}

func checkFileHashes(bundlePath string) []CheckResult {
	var results []CheckResult

	// Try manifest.json with file_hashes
	pack := openPack(bundlePath)
	defer pack.close()
	hasManifest, err := pack.hasFile("manifest.json")
	if err != nil {
		return []CheckResult{failed("file_hashes", fmt.Sprintf("cannot read manifest: %v", err))}
	}
	if hasManifest {
		data, err := pack.readFile("manifest.json")
		if err != nil {
			return []CheckResult{{Name: "file_hashes", Pass: false, Reason: fmt.Sprintf("cannot read manifest: %v", err)}}
		}

		var manifest struct {
			FileHashes map[string]string `json:"file_hashes"`
		}
		if err := json.Unmarshal(data, &manifest); err != nil {
			// A manifest that does not parse is input this check could not
			// read, not a manifest without hashes.
			return []CheckResult{failed("file_hashes", fmt.Sprintf("invalid manifest JSON: %v", err))}
		}
		if len(manifest.FileHashes) == 0 {
			return []CheckResult{notRun("file_hashes", "manifest.json declares no file_hashes")}
		}

		// Sort keys for deterministic output
		keys := make([]string, 0, len(manifest.FileHashes))
		for k := range manifest.FileHashes {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, name := range keys {
			expectedHash := manifest.FileHashes[name]
			actualHash, err := pack.hashNamed(name)
			if errors.Is(err, packfs.ErrOutside) {
				results = append(results, failed(fmt.Sprintf("hash:%s", name), fmt.Sprintf("manifest path is outside the pack, so it was not read: %v", err)))
				continue
			}
			if absent(err) {
				results = append(results, CheckResult{
					Name: fmt.Sprintf("hash:%s", name), Pass: false,
					Reason: fmt.Sprintf("file missing: %v", err),
				})
				continue
			}
			if err != nil {
				results = append(results, failed(fmt.Sprintf("hash:%s", name), fmt.Sprintf("file cannot be read: %v", err)))
				continue
			}
			if actualHash != expectedHash {
				results = append(results, CheckResult{
					Name: fmt.Sprintf("hash:%s", name), Pass: false,
					Reason: fmt.Sprintf("hash mismatch: expected %s, got %s", expectedHash, actualHash),
				})
			} else {
				results = append(results, CheckResult{
					Name:   fmt.Sprintf("hash:%s", name),
					Pass:   true,
					Detail: "SHA-256 matches manifest.json",
				})
			}
		}
	}

	if len(results) == 0 {
		results = append(results, notRun("file_hashes", "pack has no manifest.json, so there are no manifest hashes to compare"))
	}

	return results
}

func checkConnectorEvidence(bundlePath string) CheckResult {
	pack := openPack(bundlePath)
	defer pack.close()
	path := ""
	for _, candidate := range []string{
		"connector_evidence.json",
		"09_SCHEMAS/connector_evidence.json",
		"07_ATTESTATIONS/connector_evidence.json",
	} {
		present, err := pack.hasFile(candidate)
		if err != nil {
			return failed("connector_evidence", fmt.Sprintf("%s is not read: %v", candidate, err))
		}
		if present {
			path = candidate
			break
		}
	}
	if path == "" {
		return notRun("connector_evidence", "pack has no connector_evidence.json")
	}

	data, err := pack.readFile(path)
	if err != nil {
		return CheckResult{Name: "connector_evidence", Pass: false, Reason: fmt.Sprintf("cannot read connector evidence: %v", err)}
	}
	records, err := parseConnectorEvidenceRecords(data)
	if err != nil {
		return CheckResult{Name: "connector_evidence", Pass: false, Reason: err.Error()}
	}
	if len(records) == 0 {
		return CheckResult{Name: "connector_evidence", Pass: false, Reason: "connector evidence must contain at least one record"}
	}

	var failures []string
	for i, record := range records {
		for _, issue := range evidencepkg.ValidateConnectorEvidenceRecord(record) {
			failures = append(failures, fmt.Sprintf("records[%d].%s", i, issue))
		}
	}
	if len(failures) > 0 {
		return CheckResult{Name: "connector_evidence", Pass: false, Reason: strings.Join(failures, "; ")}
	}
	// ValidateConnectorEvidenceRecord checks that the fields are present and
	// well-formed. It has nothing to recompute the hashes from.
	return verified("connector_evidence", fmt.Sprintf("%d connector evidence records declare the required sha256 hashes and references; the hashes are not recomputed", len(records)))
}

func parseConnectorEvidenceRecords(data []byte) ([]evidencepkg.ConnectorEvidenceRecord, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, fmt.Errorf("connector evidence is empty")
	}
	if strings.HasPrefix(trimmed, "[") {
		var records []evidencepkg.ConnectorEvidenceRecord
		if err := json.Unmarshal(data, &records); err != nil {
			return nil, fmt.Errorf("invalid connector evidence array: %v", err)
		}
		return records, nil
	}

	var envelope struct {
		Records           []evidencepkg.ConnectorEvidenceRecord `json:"records"`
		ConnectorEvidence []evidencepkg.ConnectorEvidenceRecord `json:"connector_evidence"`
	}
	if err := json.Unmarshal(data, &envelope); err == nil {
		if len(envelope.Records) > 0 {
			return envelope.Records, nil
		}
		if len(envelope.ConnectorEvidence) > 0 {
			return envelope.ConnectorEvidence, nil
		}
	}

	var record evidencepkg.ConnectorEvidenceRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("invalid connector evidence object: %v", err)
	}
	return []evidencepkg.ConnectorEvidenceRecord{record}, nil
}
