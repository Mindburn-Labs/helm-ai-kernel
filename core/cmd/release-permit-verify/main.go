package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/releasepermit"
)

const maxInputBytes = 2 << 20

type repeatedFlag []string

func (values *repeatedFlag) String() string { return fmt.Sprint([]string(*values)) }
func (values *repeatedFlag) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func main() {
	var contextPath string
	var outputPath string
	var permitPath string
	var reviewPaths repeatedFlag
	flag.StringVar(&contextPath, "context", "", "path to release-permit context JSON")
	flag.Var(&reviewPaths, "review", "path to review JSON; provide once per required reviewer")
	flag.StringVar(&outputPath, "output", "release-permit.json", "path for the permit JSON")
	flag.StringVar(&permitPath, "verify-permit", "", "verify an existing ALLOW permit and exit")
	flag.Parse()
	if permitPath != "" {
		if contextPath != "" || len(reviewPaths) != 0 || flagWasSet("output") {
			fatal(errors.New("--verify-permit cannot be combined with --context, --review, or --output"))
		}
		var permit releasepermit.Permit
		content, err := decodeStrictFile(permitPath, &permit)
		if err != nil {
			fatal(fmt.Errorf("read permit: %w", err))
		}
		if err := releasepermit.ValidateAllowPermit(permit); err != nil {
			fatal(fmt.Errorf("validate ALLOW permit: %w", err))
		}
		if _, err := os.Stdout.Write(content); err != nil {
			fatal(fmt.Errorf("print permit: %w", err))
		}
		return
	}

	if contextPath == "" || len(reviewPaths) == 0 || outputPath == "" {
		fatal(errors.New("--context, at least one --review, and --output are required"))
	}

	var context releasepermit.Context
	contextContent, err := decodeStrictFile(contextPath, &context)
	if err != nil {
		fatal(fmt.Errorf("read context: %w", err))
	}
	contextDigest := sha256.Sum256(contextContent)
	contextSHA256 := hex.EncodeToString(contextDigest[:])
	reviews := make([]releasepermit.Review, 0, len(reviewPaths))
	for _, path := range reviewPaths {
		var review releasepermit.Review
		if _, err := decodeStrictFile(path, &review); err != nil {
			fatal(fmt.Errorf("read review %q: %w", path, err))
		}
		reviews = append(reviews, review)
	}

	permit, err := releasepermit.Evaluate(context, contextSHA256, reviews)
	if err != nil {
		fatal(fmt.Errorf("evaluate release permit: %w", err))
	}
	encoded, err := json.MarshalIndent(permit, "", "  ")
	if err != nil {
		fatal(fmt.Errorf("encode release permit: %w", err))
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(outputPath, encoded, 0o644); err != nil {
		fatal(fmt.Errorf("write release permit: %w", err))
	}
	if _, err := os.Stdout.Write(encoded); err != nil {
		fatal(fmt.Errorf("print release permit: %w", err))
	}
	if permit.Decision != releasepermit.DecisionAllow {
		os.Exit(3)
	}
}

func flagWasSet(name string) bool {
	set := false
	flag.Visit(func(current *flag.Flag) {
		if current.Name == name {
			set = true
		}
	})
	return set
}

func decodeStrictFile(path string, destination any) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > maxInputBytes {
		return nil, fmt.Errorf("input exceeds %d bytes", maxInputBytes)
	}
	// #nosec G304 -- paths are explicit command inputs in a protected workflow.
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(content) > maxInputBytes {
		return nil, fmt.Errorf("input exceeds %d bytes", maxInputBytes)
	}
	if !json.Valid(content) {
		return nil, errors.New("input is not exactly one valid JSON value")
	}
	if err := rejectDuplicateKeys(content); err != nil {
		return nil, err
	}
	if err := validateExactShape(content, destination); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("input contains more than one JSON value")
		}
		return nil, fmt.Errorf("read trailing data: %w", err)
	}
	return content, nil
}

func rejectDuplicateKeys(content []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("input contains more than one JSON value")
		}
		return fmt.Errorf("read trailing token: %w", err)
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return errors.New("object did not end with }")
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return errors.New("array did not end with ]")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	return nil
}

func validateExactShape(content []byte, destination any) error {
	root, err := decodeObject(content, "root")
	if err != nil {
		return err
	}
	switch destination.(type) {
	case *releasepermit.Context:
		if err := requireKeys(root, []string{
			"schema", "repository", "event", "pull_request", "base_ref", "base_sha",
			"head_sha", "merge_sha", "merge_tree_sha", "workflow_repository",
			"workflow_path", "workflow_ref", "workflow_sha", "run_id", "run_attempt",
			"issued_at", "authority", "required_reviewers",
		}, nil, "context"); err != nil {
			return err
		}
		if err := validateAuthority(root["authority"], "authority"); err != nil {
			return err
		}
		reviewers, err := decodeArray(root["required_reviewers"], "required_reviewers")
		if err != nil {
			return err
		}
		for index, raw := range reviewers {
			if err := validateReviewer(raw, fmt.Sprintf("required_reviewers[%d]", index)); err != nil {
				return err
			}
		}
	case *releasepermit.Review:
		if err := requireKeys(root, []string{
			"schema", "repository", "pull_request", "base_sha", "head_sha", "merge_sha",
			"merge_tree_sha", "workflow_sha",
			"run_id", "run_attempt", "context_sha256", "reviewer", "verdict",
			"response_sha256", "findings",
		}, nil, "review"); err != nil {
			return err
		}
		if err := validateReviewer(root["reviewer"], "reviewer"); err != nil {
			return err
		}
		findings, err := decodeArray(root["findings"], "findings")
		if err != nil {
			return err
		}
		for index, raw := range findings {
			finding, err := decodeObject(raw, fmt.Sprintf("findings[%d]", index))
			if err != nil {
				return err
			}
			if err := requireKeys(
				finding,
				[]string{"severity", "code", "summary"},
				[]string{"path", "line"},
				fmt.Sprintf("findings[%d]", index),
			); err != nil {
				return err
			}
		}
	case *releasepermit.Permit:
		if err := requireKeys(root, []string{
			"schema", "permit_id", "decision", "repository", "pull_request", "base_ref",
			"base_sha", "head_sha", "merge_sha", "merge_tree_sha", "workflow_repository",
			"workflow_path", "workflow_ref", "workflow_sha", "run_id", "run_attempt",
			"issued_at", "authority", "context_sha256", "reviews", "reasons",
		}, nil, "permit"); err != nil {
			return err
		}
		if err := validateAuthority(root["authority"], "authority"); err != nil {
			return err
		}
		reviews, err := decodeArray(root["reviews"], "reviews")
		if err != nil {
			return err
		}
		for index, raw := range reviews {
			review, err := decodeObject(raw, fmt.Sprintf("reviews[%d]", index))
			if err != nil {
				return err
			}
			if err := requireKeys(review, []string{
				"reviewer", "verdict", "response_sha256", "blocking_findings", "advisory_findings",
			}, nil, fmt.Sprintf("reviews[%d]", index)); err != nil {
				return err
			}
			if err := validateReviewer(review["reviewer"], fmt.Sprintf("reviews[%d].reviewer", index)); err != nil {
				return err
			}
		}
		reasons, err := decodeArray(root["reasons"], "reasons")
		if err != nil {
			return err
		}
		for index, raw := range reasons {
			reason, err := decodeObject(raw, fmt.Sprintf("reasons[%d]", index))
			if err != nil {
				return err
			}
			if err := requireKeys(reason, []string{"code", "detail"}, []string{"reviewer"}, fmt.Sprintf("reasons[%d]", index)); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unsupported strict JSON destination %T", destination)
	}
	return nil
}

func validateAuthority(raw json.RawMessage, label string) error {
	authority, err := decodeObject(raw, label)
	if err != nil {
		return err
	}
	if err := requireKeys(authority, []string{
		"schema", "generation", "kernel_sha", "gate_profiles_sha256",
		"adversarial_corpus_sha256", "parent",
	}, nil, label); err != nil {
		return err
	}
	parent := bytes.TrimSpace(authority["parent"])
	if bytes.Equal(parent, []byte("null")) {
		return nil
	}
	parentObject, err := decodeObject(parent, label+".parent")
	if err != nil {
		return err
	}
	return requireKeys(
		parentObject,
		[]string{"generation", "workflow_sha"},
		nil,
		label+".parent",
	)
}

func validateReviewer(raw json.RawMessage, label string) error {
	reviewer, err := decodeObject(raw, label)
	if err != nil {
		return err
	}
	return requireKeys(reviewer, []string{"provider", "model"}, nil, label)
}

func decodeObject(content []byte, label string) (map[string]json.RawMessage, error) {
	if trimmed := bytes.TrimSpace(content); len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, fmt.Errorf("%s must be an object", label)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(content, &object); err != nil {
		return nil, fmt.Errorf("decode %s: %w", label, err)
	}
	return object, nil
}

func decodeArray(content []byte, label string) ([]json.RawMessage, error) {
	if trimmed := bytes.TrimSpace(content); len(trimmed) == 0 || trimmed[0] != '[' {
		return nil, fmt.Errorf("%s must be an explicit array", label)
	}
	var values []json.RawMessage
	if err := json.Unmarshal(content, &values); err != nil {
		return nil, fmt.Errorf("decode %s: %w", label, err)
	}
	return values, nil
}

func requireKeys(
	object map[string]json.RawMessage,
	required []string,
	optional []string,
	label string,
) error {
	requiredSet := make(map[string]struct{}, len(required))
	allowed := make(map[string]struct{}, len(required)+len(optional))
	for _, key := range required {
		requiredSet[key] = struct{}{}
		allowed[key] = struct{}{}
	}
	for _, key := range optional {
		allowed[key] = struct{}{}
	}
	var missing, unexpected []string
	for key := range requiredSet {
		if _, ok := object[key]; !ok {
			missing = append(missing, key)
		}
	}
	for key := range object {
		if _, ok := allowed[key]; !ok {
			unexpected = append(unexpected, key)
		}
	}
	if len(missing) == 0 && len(unexpected) == 0 {
		return nil
	}
	sort.Strings(missing)
	sort.Strings(unexpected)
	return fmt.Errorf(
		"%s keys invalid; missing=%s unexpected=%s",
		label,
		strings.Join(missing, ","),
		strings.Join(unexpected, ","),
	)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "release-permit-verify:", err)
	os.Exit(2)
}
