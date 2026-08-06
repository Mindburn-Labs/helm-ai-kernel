package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/promotionpermit"
)

const maxInputBytes = 32 << 20

var promotionInputKeys = []string{
	"schema", "target_environment", "release_manifest_ref", "release_manifest_generation",
	"release_manifest_hash", "release_manifest_status", "platform_overlay_ref", "platform_overlay_hash",
	"apps_overlay_ref", "apps_overlay_hash", "protected_environment", "apps_empty_intent",
}

var trustedInputKeys = []string{
	"schema", "observed_at", "maximum_permit_ttl", "expected_policy_epoch", "emergency_fence",
	"verdict_trust", "approval_trust", "approval_consumption_ref", "approval_authority",
	"connector_release_trust", "current_connector_release", "permit", "dependency", "route_binding", "route_artifacts",
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("promotion-permit-verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var envelopePath, promotionInputPath, promotionInputRef, releaseManifestPath string
	var platformOverlayPath, appsOverlayPath, inputSchemaPath, trustPath string
	flags.StringVar(&envelopePath, "envelope", "", "immutable LaunchEffectAuthorizationEnvelope JSON")
	flags.StringVar(&promotionInputPath, "promotion-input", "", "production promotion input JSON")
	flags.StringVar(&promotionInputRef, "promotion-input-ref", "", "source-owned ref bound as promotion_permit_ref")
	flags.StringVar(&releaseManifestPath, "release-manifest", "", "trusted release manifest bytes")
	flags.StringVar(&platformOverlayPath, "platform-overlay", "", "trusted production platform overlay bytes")
	flags.StringVar(&appsOverlayPath, "apps-overlay", "", "trusted production apps overlay bytes")
	flags.StringVar(&inputSchemaPath, "input-schema", "", "source-owned DEPLOY_PRODUCTION_ACTIVATE JSON schema")
	flags.StringVar(&trustPath, "trusted-inputs", "", "source-owned approval, verdict, connector, policy, fence, permit, and route inputs")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	for name, value := range map[string]string{
		"--envelope": envelopePath, "--promotion-input": promotionInputPath,
		"--promotion-input-ref": promotionInputRef, "--release-manifest": releaseManifestPath,
		"--platform-overlay": platformOverlayPath, "--apps-overlay": appsOverlayPath,
		"--input-schema": inputSchemaPath, "--trusted-inputs": trustPath,
	} {
		if value == "" {
			return fmt.Errorf("%s is required", name)
		}
	}

	var envelope contracts.LaunchEffectAuthorizationEnvelope
	if _, err := decodeStrictFile(envelopePath, &envelope, nil); err != nil {
		return fmt.Errorf("read launch authorization envelope: %w", err)
	}
	var input promotionpermit.Input
	if _, err := decodeStrictFile(promotionInputPath, &input, promotionInputKeys); err != nil {
		return fmt.Errorf("read promotion input: %w", err)
	}
	var trust trustedInputs
	if _, err := decodeStrictFile(trustPath, &trust, trustedInputKeys); err != nil {
		return fmt.Errorf("read trusted inputs: %w", err)
	}
	releaseManifest, err := readRegularFile(releaseManifestPath)
	if err != nil {
		return fmt.Errorf("read release manifest: %w", err)
	}
	platformOverlay, err := readRegularFile(platformOverlayPath)
	if err != nil {
		return fmt.Errorf("read platform overlay: %w", err)
	}
	appsOverlay, err := readRegularFile(appsOverlayPath)
	if err != nil {
		return fmt.Errorf("read apps overlay: %w", err)
	}
	inputSchema, err := readRegularFile(inputSchemaPath)
	if err != nil {
		return fmt.Errorf("read input schema: %w", err)
	}
	launchContext, err := trust.launchContext(envelope, inputSchema)
	if err != nil {
		return fmt.Errorf("build source-owned verification context: %w", err)
	}
	if err := promotionpermit.Verify(envelope, promotionpermit.VerificationContext{
		PromotionInputRef: promotionInputRef,
		PromotionInput:    input,
		ReleaseManifest:   releaseManifest,
		PlatformOverlay:   platformOverlay,
		AppsOverlay:       appsOverlay,
		Launch:            launchContext,
	}); err != nil {
		return err
	}
	digest, err := input.Hash()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "production promotion preflight verified: %s\n", digest)
	return err
}

func decodeStrictFile(path string, destination any, requiredKeys []string) ([]byte, error) {
	content, err := readRegularFile(path)
	if err != nil {
		return nil, err
	}
	if !json.Valid(content) {
		return nil, errors.New("input is not exactly one valid JSON value")
	}
	if err := rejectDuplicateKeys(content); err != nil {
		return nil, err
	}
	if len(requiredKeys) != 0 {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(content, &object); err != nil {
			return nil, errors.New("input must be a JSON object")
		}
		actual := make([]string, 0, len(object))
		for key := range object {
			actual = append(actual, key)
		}
		sort.Strings(actual)
		expected := append([]string(nil), requiredKeys...)
		sort.Strings(expected)
		if fmt.Sprint(actual) != fmt.Sprint(expected) {
			return nil, fmt.Errorf("input keys must be exactly %v", expected)
		}
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

func readRegularFile(path string) ([]byte, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !pathInfo.Mode().IsRegular() || pathInfo.Size() > maxInputBytes {
		return nil, fmt.Errorf("input must be a regular file no larger than %d bytes", maxInputBytes)
	}
	// #nosec G304 -- every path is an explicit offline verifier input.
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	openInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !openInfo.Mode().IsRegular() || !os.SameFile(pathInfo, openInfo) {
		return nil, errors.New("input changed while opening")
	}
	content, err := io.ReadAll(io.LimitReader(file, maxInputBytes+1))
	if err != nil {
		return nil, err
	}
	if len(content) > maxInputBytes {
		return nil, fmt.Errorf("input exceeds %d bytes", maxInputBytes)
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
		return err
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
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("JSON object did not end with }")
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("JSON array did not end with ]")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	return nil
}
