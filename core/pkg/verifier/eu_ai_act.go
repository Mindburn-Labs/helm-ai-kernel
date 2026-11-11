package verifier

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// checkEUAIActEvidenceProfile validates every eu_ai_act_profile object the
// pack embeds. Nothing in the pack format requires one, so a pack without it
// leaves the check not run. It used to be counted as passed.
func checkEUAIActEvidenceProfile(bundlePath string) CheckResult {
	profiles, err := collectEUAIActEvidenceProfiles(bundlePath)
	if err != nil {
		return CheckResult{Name: "eu_ai_act_profile", Pass: false, Reason: err.Error()}
	}
	if len(profiles) == 0 {
		return notRun("eu_ai_act_profile", "no JSON file in the pack carries an eu_ai_act_profile object")
	}

	var issues []string
	for idx, profile := range profiles {
		for _, issue := range contracts.ValidateEUAIActEvidenceProfile(profile) {
			issues = append(issues, fmt.Sprintf("profile[%d]: %s", idx, issue))
		}
	}
	if len(issues) > 0 {
		return CheckResult{Name: "eu_ai_act_profile", Pass: false, Reason: strings.Join(issues, "; ")}
	}
	// ValidateEUAIActEvidenceProfile checks which fields are filled in for the
	// declared role and risk category. The documents the refs name are not in
	// reach of this verifier.
	return verified("eu_ai_act_profile", fmt.Sprintf("%d EU AI Act profile(s) carry the fields their role and risk category require; the referenced records are not resolved", len(profiles)))
}

func collectEUAIActEvidenceProfiles(bundlePath string) ([]*contracts.EUAIActEvidenceProfile, error) {
	var profiles []*contracts.EUAIActEvidenceProfile
	err := filepath.WalkDir(bundlePath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}
		info, statErr := d.Info()
		if statErr != nil {
			return statErr
		}
		if info.Size() > 2*1024*1024 {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		var document any
		if json.Unmarshal(data, &document) != nil {
			return nil
		}
		for _, raw := range findEUAIActProfileValues(document) {
			encoded, marshalErr := json.Marshal(raw)
			if marshalErr != nil {
				return marshalErr
			}
			var profile contracts.EUAIActEvidenceProfile
			if unmarshalErr := json.Unmarshal(encoded, &profile); unmarshalErr != nil {
				return fmt.Errorf("invalid eu_ai_act_profile in %s: %w", path, unmarshalErr)
			}
			profiles = append(profiles, &profile)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return profiles, nil
}

func findEUAIActProfileValues(value any) []any {
	switch typed := value.(type) {
	case map[string]any:
		var found []any
		for key, item := range typed {
			if key == "eu_ai_act_profile" {
				found = append(found, item)
				continue
			}
			found = append(found, findEUAIActProfileValues(item)...)
		}
		return found
	case []any:
		var found []any
		for _, item := range typed {
			found = append(found, findEUAIActProfileValues(item)...)
		}
		return found
	default:
		return nil
	}
}
