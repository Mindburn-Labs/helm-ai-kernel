package conformance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

func validateTONActonGoldenPacks(ctx *TestContext) error {
	cases := loadTONActonGoldenCases(ctx)
	if len(cases) < 22 {
		ctx.Fail("expected at least 22 TON Acton golden cases, got %d", len(cases))
	}
	return nil
}

func loadTONActonGoldenCases(ctx *TestContext) map[string]string {
	root, err := tonActonGoldenRoot()
	if err != nil {
		ctx.Fail("%v", err)
		return nil
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		ctx.Fail("read TON Acton golden root: %v", err)
		return nil
	}
	out := map[string]string{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, entry.Name(), "case.json"))
		if err != nil {
			ctx.Fail("read %s: %v", entry.Name(), err)
			continue
		}
		var payload struct {
			CaseID             string `json:"case_id"`
			ActionURN          string `json:"action_urn"`
			ExpectedVerdict    string `json:"expected_verdict"`
			ExpectedReasonCode string `json:"expected_reason_code"`
		}
		if err := json.Unmarshal(data, &payload); err != nil {
			ctx.Fail("decode %s: %v", entry.Name(), err)
			continue
		}
		if payload.CaseID != entry.Name() {
			ctx.Fail("%s case_id mismatch: %s", entry.Name(), payload.CaseID)
		}
		if payload.ActionURN == "" || payload.ExpectedVerdict == "" {
			ctx.Fail("%s missing action_urn or expected_verdict", entry.Name())
		}
		out[payload.CaseID] = payload.ExpectedReasonCode
	}
	return out
}

func tonActonGoldenRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("cannot resolve conformance source path")
	}
	return filepath.Join(filepath.Dir(file), "golden", "ton-acton"), nil
}
