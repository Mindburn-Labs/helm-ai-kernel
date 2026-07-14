package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

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
	var reviewPaths repeatedFlag
	flag.StringVar(&contextPath, "context", "", "path to release-permit context JSON")
	flag.Var(&reviewPaths, "review", "path to review JSON; provide once per required reviewer")
	flag.StringVar(&outputPath, "output", "release-permit.json", "path for the permit JSON")
	flag.Parse()

	if contextPath == "" || len(reviewPaths) == 0 || outputPath == "" {
		fatal(errors.New("--context, at least one --review, and --output are required"))
	}

	var context releasepermit.Context
	if err := decodeStrictFile(contextPath, &context); err != nil {
		fatal(fmt.Errorf("read context: %w", err))
	}
	reviews := make([]releasepermit.Review, 0, len(reviewPaths))
	for _, path := range reviewPaths {
		var review releasepermit.Review
		if err := decodeStrictFile(path, &review); err != nil {
			fatal(fmt.Errorf("read review %q: %w", path, err))
		}
		reviews = append(reviews, review)
	}

	permit, err := releasepermit.Evaluate(context, reviews)
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

func decodeStrictFile(path string, destination any) error {
	// #nosec G304 -- paths are explicit command inputs in a protected workflow.
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(content) > maxInputBytes {
		return fmt.Errorf("input exceeds %d bytes", maxInputBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("input contains more than one JSON value")
		}
		return fmt.Errorf("read trailing data: %w", err)
	}
	return nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "release-permit-verify:", err)
	os.Exit(2)
}
