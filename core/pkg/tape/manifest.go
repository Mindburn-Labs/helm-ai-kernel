package tape

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
)

// WriteManifest writes tape_manifest.json to the given directory per §5.3.
func WriteManifest(dir string, manifest *Manifest) error {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal tape manifest: %w", err)
	}
	path := filepath.Join(dir, "tape_manifest.json")
	return os.WriteFile(path, data, 0600)
}

// ReadManifest reads tape_manifest.json from the given directory.
func ReadManifest(dir string) (*Manifest, error) {
	path := filepath.Join(dir, "tape_manifest.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read tape manifest: %w", err)
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parse tape manifest: %w", err)
	}
	return &manifest, nil
}

// VerifyManifestIntegrity compares the manifest with the tape entries and
// returns every difference: a manifest row with no entry, a sequence number
// listed more than once, and any field a manifest row carries that does not
// equal the entry it names.
//
// sha256 and size_bytes are compared with the entry's value; every other field
// is compared with the entry field of the same name. A field the entry has no
// counterpart for cannot be compared, and that is reported too: a manifest
// statement nothing was checked against must not read as a match.
func VerifyManifestIntegrity(entries []Entry, manifest *Manifest) []string {
	var issues []string
	entryMap := make(map[uint64]*Entry, len(entries))
	for i := range entries {
		entryMap[entries[i].Seq] = &entries[i]
	}

	listed := make(map[uint64]int, len(manifest.Entries))
	for _, item := range manifest.Entries {
		listed[item.Seq]++
	}
	reported := make(map[uint64]bool, len(listed))
	for _, item := range manifest.Entries {
		if listed[item.Seq] > 1 && !reported[item.Seq] {
			reported[item.Seq] = true
			issues = append(issues, fmt.Sprintf("seq=%d is listed %d times in tape_manifest.json", item.Seq, listed[item.Seq]))
		}
		entry, ok := entryMap[item.Seq]
		if !ok {
			issues = append(issues, fmt.Sprintf("seq=%d referenced in manifest but not in entries", item.Seq))
			continue
		}
		issues = append(issues, compareManifestItem(item, entry)...)
	}
	return issues
}

// compareManifestItem returns one issue per field of item that does not equal
// entry, in field-name order.
func compareManifestItem(item ManifestItem, entry *Entry) []string {
	carried, err := item.carriedFields()
	if err != nil {
		return []string{fmt.Sprintf("seq=%d manifest row cannot be read field by field: %v", item.Seq, err)}
	}
	recorded, err := jsonFields(entry)
	if err != nil {
		return []string{fmt.Sprintf("seq=%d tape entry cannot be read field by field: %v", item.Seq, err)}
	}
	names := make([]string, 0, len(carried))
	for name := range carried {
		names = append(names, name)
	}
	sort.Strings(names)

	var issues []string
	for _, name := range names {
		switch name {
		case "seq":
			// The row was matched to the entry by this field.
		case "sha256":
			h := sha256.Sum256(entry.Value)
			if computed := hex.EncodeToString(h[:]); computed != item.SHA256 {
				issues = append(issues, fmt.Sprintf("seq=%d hash mismatch: expected %s, got %s", item.Seq, item.SHA256, computed))
			}
		case "size_bytes":
			if size := int64(len(entry.Value)); size != item.SizeBytes {
				issues = append(issues, fmt.Sprintf("seq=%d manifest field \"size_bytes\" is %d, tape entry value is %d bytes", item.Seq, item.SizeBytes, size))
			}
		default:
			want, ok := recorded[name]
			if !ok {
				issues = append(issues, fmt.Sprintf("seq=%d manifest field %q has no counterpart on the tape entry, so it cannot be compared", item.Seq, name))
				continue
			}
			if !sameJSON(carried[name], want) {
				issues = append(issues, fmt.Sprintf("seq=%d manifest field %q is %s, tape entry has %s", item.Seq, name, compactJSON(carried[name]), compactJSON(want)))
			}
		}
	}
	return issues
}

// UnmarshalJSON keeps the row's fields as written beside the typed ones, so
// VerifyManifestIntegrity can compare a field this struct does not declare,
// such as component_id.
func (item *ManifestItem) UnmarshalJSON(data []byte) error {
	type typed ManifestItem
	var decoded typed
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	*item = ManifestItem(decoded)
	item.fields = fields
	return nil
}

// carriedFields is the row as JSON fields: the ones it was read with, or, for
// a row built in memory, the ones it marshals to.
func (item ManifestItem) carriedFields() (map[string]json.RawMessage, error) {
	if item.fields != nil {
		return item.fields, nil
	}
	return jsonFields(item)
}

func jsonFields(v any) (map[string]json.RawMessage, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	return fields, nil
}

// sameJSON reports whether two JSON values are equal as values, whatever their
// spacing or key order.
func sameJSON(a, b json.RawMessage) bool {
	var left, right any
	if json.Unmarshal(a, &left) != nil || json.Unmarshal(b, &right) != nil {
		return false
	}
	return reflect.DeepEqual(left, right)
}

func compactJSON(raw json.RawMessage) string {
	var out bytes.Buffer
	if err := json.Compact(&out, raw); err != nil {
		return string(raw)
	}
	return out.String()
}
