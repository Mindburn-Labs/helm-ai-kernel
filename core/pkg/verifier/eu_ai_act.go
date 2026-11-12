package verifier

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// checkEUAIActEvidenceProfile validates every eu_ai_act_profile object the
// pack embeds. Nothing in the pack format requires one, so a pack without it
// leaves the check not run. It used to be counted as passed.
//
// Every .json file is read, whatever its size: a file skipped for being large
// could carry an invalid profile while the check said the pack carries none.
func checkEUAIActEvidenceProfile(bundlePath string) CheckResult {
	const name = "eu_ai_act_profile"
	scan, err := collectEUAIActEvidenceProfiles(bundlePath)
	if err != nil {
		return failed(name, err.Error())
	}
	// Files that do not parse were read up to the first error and showed no
	// profile. They are counted in the result, so it does not claim to have
	// read them.
	unparsed := ""
	if len(scan.unparsed) > 0 {
		unparsed = fmt.Sprintf("%d of %d .json files do not parse as JSON and were read only up to the first error (%s)",
			len(scan.unparsed), scan.files, summarizeNames(scan.unparsed, 5))
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

	var issues []string
	for idx, profile := range scan.profiles {
		for _, issue := range contracts.ValidateEUAIActEvidenceProfile(profile) {
			issues = append(issues, fmt.Sprintf("profile[%d]: %s", idx, issue))
		}
	}
	if len(issues) > 0 {
		return failed(name, strings.Join(issues, "; "))
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
	// files counts the .json files the walk opened.
	files int
	// unparsed names, relative to the pack, the files that stopped parsing as
	// JSON before any profile was found in them.
	unparsed []string
}

func collectEUAIActEvidenceProfiles(bundlePath string) (euAIActScan, error) {
	var scan euAIActScan
	err := filepath.WalkDir(bundlePath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}
		name := path
		if rel, relErr := filepath.Rel(bundlePath, path); relErr == nil {
			name = filepath.ToSlash(rel)
		}
		scan.files++
		values, parseErr := readEUAIActProfileValues(path)
		if parseErr != nil {
			var syntax *jsonSyntaxError
			if !errors.As(parseErr, &syntax) {
				return parseErr
			}
			if len(values) == 0 {
				scan.unparsed = append(scan.unparsed, name)
				return nil
			}
			// A profile sits in a file that is damaged further on. A reader
			// that needs the whole document cannot use it.
			return fmt.Errorf("%s carries an eu_ai_act_profile but does not parse as JSON: %v", name, syntax.err)
		}
		for _, raw := range values {
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

// jsonSyntaxError marks a file whose content stopped being JSON, as opposed
// to a file that could not be opened or read.
type jsonSyntaxError struct{ err error }

func (e *jsonSyntaxError) Error() string { return e.err.Error() }

// readEUAIActProfileValues streams one file and returns the value of every
// "eu_ai_act_profile" key in it, at any depth, in every JSON document the file
// holds (a line-delimited file holds several).
//
// It reads tokens instead of building the document, so a file of any size is
// searched and a key that appears twice in one object is seen twice. The key
// is matched after JSON unescaping, the way a reader of the file sees it. On a
// syntax error it returns the values found before the error with a
// *jsonSyntaxError.
func readEUAIActProfileValues(path string) ([]json.RawMessage, error) {
	file, err := os.Open(path) // #nosec G304 -- the path comes from walking the pack directory the caller asked to verify
	if err != nil {
		return nil, err
	}
	defer file.Close()

	decoder := json.NewDecoder(bufio.NewReader(file))
	var values []json.RawMessage
	for {
		err := scanEUAIActProfileValues(decoder, &values, true)
		if err == io.EOF {
			return values, nil
		}
		if err != nil {
			var pathErr *os.PathError
			if errors.As(err, &pathErr) {
				return values, err
			}
			return values, &jsonSyntaxError{err: err}
		}
	}
}

// scanEUAIActProfileValues consumes one JSON value from the decoder. A value
// under the profile key is captured whole and not searched further. io.EOF is
// returned only for a clean end before a top-level value.
func scanEUAIActProfileValues(decoder *json.Decoder, values *[]json.RawMessage, topLevel bool) error {
	token, err := decoder.Token()
	if err != nil {
		if err == io.EOF && !topLevel {
			return io.ErrUnexpectedEOF
		}
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return unexpectedEOF(err)
			}
			if key, _ := keyToken.(string); key == "eu_ai_act_profile" {
				var raw json.RawMessage
				if err := decoder.Decode(&raw); err != nil {
					return unexpectedEOF(err)
				}
				*values = append(*values, raw)
				continue
			}
			if err := scanEUAIActProfileValues(decoder, values, false); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := scanEUAIActProfileValues(decoder, values, false); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected %q", delim)
	}
	// The closing delimiter. More() is also false at the end of the input, so
	// a truncated document ends here with io.EOF.
	if _, err := decoder.Token(); err != nil {
		return unexpectedEOF(err)
	}
	return nil
}

func unexpectedEOF(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}

// summarizeNames joins up to limit names and says how many it left out.
func summarizeNames(names []string, limit int) string {
	if len(names) <= limit {
		return strings.Join(names, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(names[:limit], ", "), len(names)-limit)
}
