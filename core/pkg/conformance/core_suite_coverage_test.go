package conformance

import (
	"errors"
	"strings"
	"testing"
)

func TestSuiteRunResultBranches(t *testing.T) {
	suite := NewSuite()
	suite.Register(TestCase{
		ID:    "positive-error",
		Level: LevelL1,
		Name:  "positive returns error",
		Run: func(*TestContext) error {
			return errors.New("boom")
		},
	})
	suite.Register(TestCase{
		ID:    "positive-assertion",
		Level: LevelL1,
		Name:  "positive assertion failure",
		Run: func(ctx *TestContext) error {
			ctx.Fail("failed %s", "assertion")
			return nil
		},
	})
	suite.Register(TestCase{
		ID:       "negative-unexpected-pass",
		Level:    LevelL1,
		Name:     "negative unexpectedly passes",
		Negative: true,
		Run: func(*TestContext) error {
			return nil
		},
	})
	suite.Register(TestCase{
		ID:       "negative-context-failure",
		Level:    LevelL1,
		Name:     "negative context failure",
		Negative: true,
		Run: func(ctx *TestContext) error {
			ctx.Fail("expected deny")
			return nil
		},
	})
	suite.Register(TestCase{
		ID:       "negative-error",
		Level:    LevelL1,
		Name:     "negative error",
		Negative: true,
		Run: func(*TestContext) error {
			return errors.New("expected deny")
		},
	})

	results := suite.Run(LevelL1)
	byID := map[string]TestResult{}
	for _, result := range results {
		byID[result.TestID] = result
	}

	if byID["positive-error"].Passed || !strings.Contains(byID["positive-error"].Error, "boom") {
		t.Fatalf("positive error result = %+v, want failed with boom", byID["positive-error"])
	}
	if byID["positive-assertion"].Passed || !strings.Contains(byID["positive-assertion"].Error, "assertion") {
		t.Fatalf("positive assertion result = %+v, want assertion failure", byID["positive-assertion"])
	}
	if byID["negative-unexpected-pass"].Passed || !strings.Contains(byID["negative-unexpected-pass"].Error, "unexpectedly") {
		t.Fatalf("negative unexpected pass result = %+v, want failed unexpected-pass result", byID["negative-unexpected-pass"])
	}
	if !byID["negative-context-failure"].Passed {
		t.Fatalf("negative context failure result = %+v, want passed", byID["negative-context-failure"])
	}
	if !byID["negative-error"].Passed {
		t.Fatalf("negative error result = %+v, want passed", byID["negative-error"])
	}
}
