package verifier

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier/packfs"
)

// euAIActProfileKey is the member name the scan looks for, in any letter
// case.
const euAIActProfileKey = "eu_ai_act_profile"

// maxEUAIActProfiles is the most eu_ai_act_profile members the scan validates
// in one pack. A pack that holds more fails by the name of the file where the
// count passes it: every member is unmarshalled and validated, so the count
// needs a bound of its own beside the byte limits.
const maxEUAIActProfiles = 1024

// maxEUAIActIssues is the most validation issues the reason lists; it counts
// the rest.
const maxEUAIActIssues = 10

// maxJSONDepth is the nesting depth encoding/json accepts. The scan never
// goes deeper; a document that does is one that does not parse.
const maxJSONDepth = 10000

var (
	// euAIActScanFileLimit is the most the scan reads of one .json file.
	euAIActScanFileLimit = packfs.MaxFileBytes
	// euAIActScanPackLimit is the most the scan reads over the whole pack.
	// Every .json file in the pack is read, indexed or not, so the total has
	// a bound of its own.
	euAIActScanPackLimit int64 = 256 << 20
)

// checkEUAIActEvidenceProfile validates every eu_ai_act_profile object the
// pack embeds. Nothing in the pack format requires one, so a pack without it
// leaves the check not run. It used to be counted as passed.
//
// Every .json file is read, up to euAIActScanFileLimit per file and
// euAIActScanPackLimit for the pack. A file the scan did not read, because it
// is over a limit, not a regular file or outside the pack, fails the check by
// name: it could carry an invalid profile while the check said the pack
// carries none. So does the file that brings the pack past
// maxEUAIActProfiles profiles.
func checkEUAIActEvidenceProfile(bundlePath string) CheckResult {
	const name = "eu_ai_act_profile"
	pack := openPack(bundlePath)
	defer pack.close()
	scan, err := collectEUAIActEvidenceProfiles(pack)
	if err != nil {
		return failed(name, err.Error())
	}
	// Files that do not parse were searched for the member name and showed
	// none. They are counted in the result, so it does not claim to have read
	// them as JSON.
	unparsed := ""
	if len(scan.unparsed) > 0 {
		unparsed = fmt.Sprintf("%d of %d .json files do not parse as JSON and do not name an eu_ai_act_profile member (%s)",
			len(scan.unparsed), scan.files, summarizeNames(scan.unparsed, 5))
	}

	var issues []string
	if len(scan.unread) > 0 {
		issues = append(issues, fmt.Sprintf("%d .json files were not read, so an eu_ai_act_profile in them cannot be validated: %s",
			len(scan.unread), summarizeNames(scan.unread, 5)))
	}
	for idx, profile := range scan.profiles {
		for _, issue := range contracts.ValidateEUAIActEvidenceProfile(profile) {
			issues = append(issues, fmt.Sprintf("profile[%d]: %s", idx, issue))
		}
	}
	if len(issues) > 0 {
		return failed(name, summarizeIssues(issues, maxEUAIActIssues))
	}
	if len(scan.profiles) == 0 {
		switch {
		case scan.files == 0:
			return notRun(name, "the pack holds no .json file, so nothing carries an eu_ai_act_profile object")
		case unparsed != "":
			return notRun(name, "no eu_ai_act_profile object was found; "+unparsed)
		default:
			return notRun(name, fmt.Sprintf("none of the %d .json files in the pack carries an eu_ai_act_profile object", scan.files))
		}
	}
	// ValidateEUAIActEvidenceProfile checks which fields are filled in for the
	// declared role and risk category. The documents the refs name are not in
	// reach of this verifier.
	detail := fmt.Sprintf("%d EU AI Act profile(s) carry the fields their role and risk category require; the referenced records are not resolved", len(scan.profiles))
	if unparsed != "" {
		detail += "; " + unparsed
	}
	return verified(name, detail)
}

// euAIActScan is what a walk over the pack's .json files found.
type euAIActScan struct {
	profiles []*contracts.EUAIActEvidenceProfile
	// files counts the .json files the scan read.
	files int
	// unparsed names, relative to the pack, the files that do not parse as
	// JSON and in which no profile member was found.
	unparsed []string
	// unread names the .json files the scan did not read, each with why.
	unread []string
}

func collectEUAIActEvidenceProfiles(pack *packFiles) (euAIActScan, error) {
	var scan euAIActScan
	var scanned int64
	budgetSpent := false
	err := pack.walk(".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || path.Ext(name) != ".json" {
			return nil
		}
		if budgetSpent {
			scan.unread = append(scan.unread, name+" (past the "+packfs.Bytes(euAIActScanPackLimit)+" the scan reads per pack)")
			return nil
		}
		data, readErr := readEUAIActFile(pack, name, euAIActScanPackLimit-scanned)
		var overBudget *scanBudgetError
		switch {
		case errors.As(readErr, &overBudget):
			budgetSpent = true
			scan.unread = append(scan.unread, name+" (past the "+packfs.Bytes(euAIActScanPackLimit)+" the scan reads per pack)")
			return nil
		case errors.Is(readErr, packfs.ErrTooLarge):
			scan.unread = append(scan.unread, name+" (over the "+packfs.Bytes(euAIActScanFileLimit)+" per-file limit)")
			return nil
		case errors.Is(readErr, packfs.ErrOutside), errors.Is(readErr, packfs.ErrNotRegular):
			scan.unread = append(scan.unread, fmt.Sprintf("%s (%v)", name, readErr))
			return nil
		case readErr != nil:
			return readErr
		}
		scanned += int64(len(data))
		scan.files++

		room := maxEUAIActProfiles - len(scan.profiles)
		found := scanEUAIActFile(data, room)
		if len(found.values) > room {
			return fmt.Errorf("%s brings the pack past %d eu_ai_act_profile members, the most the scan validates in one pack; the members past that are not validated",
				name, maxEUAIActProfiles)
		}
		if found.syntaxErr != nil {
			if !found.keySeen {
				scan.unparsed = append(scan.unparsed, name)
				return nil
			}
			// A profile member sits in a file that does not parse. A reader
			// that needs the whole document cannot use it.
			return fmt.Errorf("%s carries an eu_ai_act_profile but does not parse as JSON: %v", name, found.syntaxErr)
		}
		for _, raw := range found.values {
			var profile contracts.EUAIActEvidenceProfile
			if unmarshalErr := json.Unmarshal(raw, &profile); unmarshalErr != nil {
				return fmt.Errorf("invalid eu_ai_act_profile in %s: %w", name, unmarshalErr)
			}
			scan.profiles = append(scan.profiles, &profile)
		}
		return nil
	})
	if err != nil {
		return euAIActScan{}, err
	}
	return scan, nil
}

// scanBudgetError marks a file the per-pack budget has no room left for.
type scanBudgetError struct{}

func (*scanBudgetError) Error() string { return "the scan budget for the pack is spent" }

// readEUAIActFile reads one .json file of the pack whole, when it fits both
// the per-file limit and the room left in the pack budget.
func readEUAIActFile(pack *packFiles, name string, room int64) ([]byte, error) {
	file, info, err := pack.openRegular(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	if info.Size() > euAIActScanFileLimit {
		return nil, fmt.Errorf("%w: %s", packfs.ErrTooLarge, name)
	}
	if info.Size() > room {
		return nil, &scanBudgetError{}
	}
	limit := min(euAIActScanFileLimit, room)
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		// The file grew after it was described.
		if limit == room {
			return nil, &scanBudgetError{}
		}
		return nil, fmt.Errorf("%w: %s", packfs.ErrTooLarge, name)
	}
	return data, nil
}

// euAIActFileScan is what one file showed.
type euAIActFileScan struct {
	// values are the raw values of the complete eu_ai_act_profile members, at
	// any depth, in every JSON document of the file, up to one more than the
	// limit scanEUAIActFile was given.
	values []json.RawMessage
	// keySeen is set when the file names the member anywhere, whether or not
	// its value could be read.
	keySeen bool
	// syntaxErr is why the file stopped being JSON, or nil.
	syntaxErr error
}

var utf8BOM = []byte{0xef, 0xbb, 0xbf}

// scanEUAIActFile finds the eu_ai_act_profile members in a file, in every
// JSON document it holds (a line-delimited file holds several). It stops
// capturing values at limit+1, so a caller sees that a file holds more than
// limit without the file costing memory per member.
//
// A leading UTF-8 byte order mark is skipped, as JSON readers that accept one
// do. Each document is checked by encoding/json, which refuses nesting deeper
// than 10000, and then searched byte by byte with an explicit stack, so a
// file of any shape costs time and memory in proportion to its size and
// nothing recurses. The member name is matched after JSON unescaping and in
// any letter case, the way encoding/json matches a member to a struct field,
// and a name that appears twice in one object is seen twice. A value under
// the member is captured whole and not searched further.
//
// When a document does not parse, the rest of the file is still searched for
// the member, and a file that holds the member name anywhere, in any letter
// case, even as raw text in damaged bytes, sets keySeen: a profile a reader
// cannot use must not read as a pack that carries none.
func scanEUAIActFile(data []byte, limit int) euAIActFileScan {
	data = bytes.TrimPrefix(data, utf8BOM)
	// Most files hold one document. json.Valid checks it in place, under the
	// same depth limit, without the copy the decoder buffers.
	if json.Valid(data) {
		values, seen := findMemberValues(data, euAIActProfileKey, limit+1)
		return euAIActFileScan{values: values, keySeen: seen}
	}
	var out euAIActFileScan
	decoder := json.NewDecoder(bytes.NewReader(data))
	for len(out.values) <= limit {
		start := int(decoder.InputOffset())
		err := decoder.Decode(&jsonSkip{})
		if err == io.EOF {
			return out
		}
		if err != nil {
			values, seen := findMemberValues(data[start:], euAIActProfileKey, limit+1-len(out.values))
			out.values = append(out.values, values...)
			out.keySeen = out.keySeen || seen || containsFold(data, euAIActProfileKey)
			out.syntaxErr = err
			return out
		}
		values, seen := findMemberValues(data[start:int(decoder.InputOffset())], euAIActProfileKey, limit+1-len(out.values))
		out.values = append(out.values, values...)
		out.keySeen = out.keySeen || seen
	}
	return out
}

// containsFold reports whether data holds key, an ASCII name, in any letter
// case. No rune outside ASCII folds to a letter of euAIActProfileKey, so
// comparing bytes finds every spelling strings.EqualFold accepts.
func containsFold(data []byte, key string) bool {
	first := key[0] | 0x20
	for i := 0; i+len(key) <= len(data); i++ {
		if data[i]|0x20 == first && bytes.EqualFold(data[i:i+len(key)], []byte(key)) {
			return true
		}
	}
	return false
}

// jsonSkip lets encoding/json check a document without building it.
type jsonSkip struct{}

func (*jsonSkip) UnmarshalJSON([]byte) error { return nil }

// findMemberValues returns the raw value of every member named key in data,
// up to limit values, and whether a member of that name was seen at all. data
// is a JSON document, or bytes that stop being one somewhere: the scan stops
// at the end of data, at limit values, at a member value that does not end, and
// at nesting deeper than maxJSONDepth. It keeps its own stack and never
// recurses.
func findMemberValues(data []byte, key string, limit int) ([]json.RawMessage, bool) {
	type frame struct{ object, wantKey bool }
	var stack []frame
	var values []json.RawMessage
	seen := false
	for i := 0; i < len(data); {
		switch data[i] {
		case '"':
			end := jsonStringEnd(data, i)
			if end < 0 {
				return values, seen
			}
			top := len(stack) - 1
			if top < 0 || !stack[top].object || !stack[top].wantKey {
				i = end
				continue
			}
			stack[top].wantKey = false
			if !memberNameIs(data[i:end], key) {
				i = end
				continue
			}
			seen = true
			colon := skipJSONSpace(data, end)
			if colon >= len(data) || data[colon] != ':' {
				i = end
				continue
			}
			valueStart := skipJSONSpace(data, colon+1)
			valueEnd := jsonValueEnd(data, valueStart)
			if valueEnd < 0 {
				return values, seen
			}
			values = append(values, json.RawMessage(data[valueStart:valueEnd]))
			if len(values) >= limit {
				return values, seen
			}
			i = valueEnd
		case '{':
			if len(stack) >= maxJSONDepth {
				return values, seen
			}
			stack = append(stack, frame{object: true, wantKey: true})
			i++
		case '[':
			if len(stack) >= maxJSONDepth {
				return values, seen
			}
			stack = append(stack, frame{})
			i++
		case '}', ']':
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			i++
		case ',':
			if top := len(stack) - 1; top >= 0 && stack[top].object {
				stack[top].wantKey = true
			}
			i++
		default:
			i++
		}
	}
	return values, seen
}

// memberNameIs reports whether the JSON string raw, quotes included, decodes
// to key in any letter case (strings.EqualFold, which is how encoding/json
// matches a member to a struct field). Letters and the underscore can only be
// escaped as \uXXXX, and no rune outside ASCII folds to a letter of the key,
// so a raw name longer than six bytes per character of key cannot decode to
// it.
func memberNameIs(raw []byte, key string) bool {
	if !bytes.ContainsRune(raw, '\\') {
		return bytes.EqualFold(raw[1:len(raw)-1], []byte(key))
	}
	if len(raw) > 2+6*len(key) {
		return false
	}
	var name string
	return json.Unmarshal(raw, &name) == nil && strings.EqualFold(name, key)
}

// jsonStringEnd returns the index after the closing quote of the string that
// starts at data[i], or -1 when data ends first.
func jsonStringEnd(data []byte, i int) int {
	for j := i + 1; j < len(data); j++ {
		switch data[j] {
		case '\\':
			j++
		case '"':
			return j + 1
		}
	}
	return -1
}

// jsonValueEnd returns the index after the value that starts at data[i], or
// -1 when data ends before it does. Containers are matched with a counter.
func jsonValueEnd(data []byte, i int) int {
	if i >= len(data) {
		return -1
	}
	switch data[i] {
	case '"':
		return jsonStringEnd(data, i)
	case '{', '[':
		depth := 0
		for j := i; j < len(data); j++ {
			switch data[j] {
			case '"':
				end := jsonStringEnd(data, j)
				if end < 0 {
					return -1
				}
				j = end - 1
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 {
					return j + 1
				}
			}
		}
		return -1
	default:
		for j := i; j < len(data); j++ {
			switch data[j] {
			case ',', '}', ']', ' ', '\t', '\r', '\n':
				if j == i {
					return -1
				}
				return j
			}
		}
		return -1
	}
}

func skipJSONSpace(data []byte, i int) int {
	for i < len(data) && (data[i] == ' ' || data[i] == '\t' || data[i] == '\r' || data[i] == '\n') {
		i++
	}
	return i
}

// summarizeNames joins up to limit names and says how many it left out.
func summarizeNames(names []string, limit int) string {
	if len(names) <= limit {
		return strings.Join(names, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(names[:limit], ", "), len(names)-limit)
}
