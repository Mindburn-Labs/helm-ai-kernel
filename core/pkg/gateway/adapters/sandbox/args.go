package sandbox

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

// The argument types. Admission has already checked the original bytes against
// the declared schema; these parsers repeat the bounds because the adapter
// acts on them (and a drift test keeps the two in step).

type createArgs struct {
	Schema         string `json:"schema"`
	Runtime        string `json:"runtime"`
	CPUMillis      int64  `json:"cpu_millis"`
	MemoryMB       int64  `json:"memory_mb"`
	DiskMB         int64  `json:"disk_mb"`
	TimeoutSeconds int64  `json:"timeout_seconds"`
	MaxProcesses   int64  `json:"max_processes"`
	EgressDisabled bool   `json:"egress_disabled"`
}

type execArgs struct {
	Schema         string   `json:"schema"`
	Command        []string `json:"command"`
	Workdir        string   `json:"workdir"`
	TimeoutSeconds int64    `json:"timeout_seconds"`
}

type terminateArgs struct {
	Schema string `json:"schema"`
}

var (
	runtimePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$`)
	workdirPattern = regexp.MustCompile(`^(/[A-Za-z0-9._/@+=,: -]*)?$`)
)

func schemaViolation(format string, args ...any) *adapters.Refusal {
	return adapters.Refuse(contracts.ReasonSchemaViolation, format, args...)
}

// decode reads raw as one closed object into v. The arguments are the exact
// bytes the permit's digest covers, so nothing is normalized.
func decode(raw []byte, v any) *adapters.Refusal {
	if len(raw) == 0 || len(raw) > effectargs.MaxBytes || !utf8.Valid(raw) {
		return schemaViolation("the arguments are not bounded UTF-8 JSON")
	}
	if err := effectargs.CheckNoDuplicateKeys(raw); err != nil {
		return schemaViolation("%v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return schemaViolation("the arguments are not the effect's closed object: %v", err)
	}
	if dec.More() {
		return schemaViolation("the arguments hold more than one JSON value")
	}
	return nil
}

func inRange(name string, v, lo, hi int64) *adapters.Refusal {
	if v < lo || v > hi {
		return schemaViolation("%s must be %d to %d", name, lo, hi)
	}
	return nil
}

func parseCreate(raw []byte) (createArgs, *adapters.Refusal) {
	var a createArgs
	if r := decode(raw, &a); r != nil {
		return a, r
	}
	switch {
	case a.Schema != createSchemaID:
		return a, schemaViolation("schema must be %s", createSchemaID)
	case !runtimePattern.MatchString(a.Runtime):
		return a, schemaViolation("runtime is not a template or image reference")
	}
	for _, c := range []struct {
		name      string
		v, lo, hi int64
	}{
		{"cpu_millis", a.CPUMillis, 100, 16000},
		{"memory_mb", a.MemoryMB, 64, 65536},
		{"disk_mb", a.DiskMB, 0, 204800},
		{"timeout_seconds", a.TimeoutSeconds, 1, 86400},
		{"max_processes", a.MaxProcesses, 0, 32768},
	} {
		if r := inRange(c.name, c.v, c.lo, c.hi); r != nil {
			return a, r
		}
	}
	return a, nil
}

func parseExec(raw []byte) (execArgs, *adapters.Refusal) {
	var a execArgs
	if r := decode(raw, &a); r != nil {
		return a, r
	}
	if a.Schema != execSchemaID {
		return a, schemaViolation("schema must be %s", execSchemaID)
	}
	if len(a.Command) < 1 || len(a.Command) > 64 {
		return a, schemaViolation("command must hold 1 to 64 arguments")
	}
	for i, c := range a.Command {
		if len(c) < 1 || len(c) > 4096 {
			return a, schemaViolation("command[%d] must be 1 to 4096 bytes", i)
		}
		if strings.ContainsRune(c, 0) {
			return a, schemaViolation("command[%d] holds a NUL byte", i)
		}
	}
	if len(a.Workdir) > 512 || !workdirPattern.MatchString(a.Workdir) || strings.Contains(a.Workdir, "..") {
		return a, schemaViolation("workdir must be empty or a plain absolute path")
	}
	return a, inRange("timeout_seconds", a.TimeoutSeconds, 1, 3600)
}

func parseTerminate(raw []byte) (terminateArgs, *adapters.Refusal) {
	var a terminateArgs
	if r := decode(raw, &a); r != nil {
		return a, r
	}
	if a.Schema != terminateSchemaID {
		return a, schemaViolation("schema must be %s", terminateSchemaID)
	}
	return a, nil
}

// describe is a bounded error text for a detail string.
func describe(err error) string {
	s := fmt.Sprint(err)
	if len(s) > 300 {
		s = s[:300]
	}
	return strings.ToValidUTF8(s, "?")
}
