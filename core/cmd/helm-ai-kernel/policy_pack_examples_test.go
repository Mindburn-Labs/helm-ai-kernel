package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPolicyPackExamplesLoad(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get cwd: %v", err)
	}
	root := filepath.Clean(filepath.Join(cwd, "../../.."))
	matches, err := filepath.Glob(filepath.Join(root, "examples", "policy-packs", "policy.*.toml"))
	if err != nil {
		t.Fatalf("glob policy packs: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("expected at least one policy-pack example")
	}

	for _, path := range matches {
		t.Run(filepath.Base(path), func(t *testing.T) {
			runtime, err := loadServePolicyRuntime(path)
			if err != nil {
				t.Fatalf("load serve policy runtime: %v", err)
			}
			if runtime.Policy == nil {
				t.Fatal("policy runtime missing policy")
			}
			if runtime.Graph == nil || len(runtime.Graph.Rules) == 0 {
				t.Fatal("policy pack compiled to an empty graph")
			}
			if runtime.ReferencePackHash == "" {
				t.Fatal("policy pack missing reference pack hash")
			}
			if hash, err := runtime.Graph.ContentHash(); err != nil {
				t.Fatalf("content hash: %v", err)
			} else if hash == "" {
				t.Fatal("policy graph content hash is empty")
			}
		})
	}
}
