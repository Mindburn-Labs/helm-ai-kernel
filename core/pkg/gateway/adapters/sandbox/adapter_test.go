package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/actuators"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
)

const tenantA, tenantB = "tenant-a", "tenant-b"

func artifactOf(t *testing.T, obs *adapters.Observation) map[string]any {
	t.Helper()
	require.NotNil(t, obs)
	require.NotNil(t, obs.Artifact)
	var out map[string]any
	require.NoError(t, json.Unmarshal(obs.Artifact.CanonicalBytes, &out))
	return out
}

// createSandbox runs a create effect for tenant to SUCCEEDED and returns the
// sandbox id.
func createSandbox(t *testing.T, ta *testAdapter, tenant string) string {
	t.Helper()
	e := effectFor(EffectCreate, "sandbox/e2b", createArgsJSON, tenant, attemptID(t))
	d := ta.Dispatch(t.Context(), &staticToken{token: testKey}, e, digest(createArgsJSON))
	require.Equal(t, adapters.DispatchSent, d.Status, d.Detail)
	o := ta.Observe(t.Context(), &staticToken{token: testKey}, e)
	require.Equal(t, adapters.OutcomeSucceeded, o.Outcome, o.Detail)
	return artifactOf(t, o.Observation)["sandbox_id"].(string)
}

func TestDeclarationsCompileAndTheirParsersAgreeWithTheirSchemas(t *testing.T) {
	ta := newTestAdapter(t, newMem())
	decls := ta.Declarations()
	require.Len(t, decls, 3)
	schemas := map[string]*adapters.ArgumentSchema{}
	for _, d := range decls {
		s, err := adapters.CompileArgumentSchema(d)
		require.NoError(t, err, d.EffectType)
		require.NotNil(t, s, d.EffectType)
		schemas[d.EffectType] = s
		r, err := adapters.CompileResultSchema(d)
		require.NoError(t, err, d.EffectType)
		require.NotNil(t, r, d.EffectType)
		assert.True(t, d.Grantable)
		assert.NotEmpty(t, d.TargetForm)
	}
	type tc struct {
		name, effect, args string
		ok                 bool
	}
	run := func(c tc) {
		t.Run(c.name, func(t *testing.T) {
			schemaErr := schemas[c.effect].Validate([]byte(c.args))
			var parseErr *adapters.Refusal
			switch c.effect {
			case EffectCreate:
				_, parseErr = parseCreate([]byte(c.args))
			case EffectExec:
				_, parseErr = parseExec([]byte(c.args))
			default:
				_, parseErr = parseTerminate([]byte(c.args))
			}
			assert.Equal(t, c.ok, schemaErr == nil, "schema: %v", schemaErr)
			assert.Equal(t, c.ok, parseErr == nil, "parser: %v", parseErr)
		})
	}
	create := func(mod func(m map[string]any)) string {
		var m map[string]any
		require.NoError(t, json.Unmarshal([]byte(createArgsJSON), &m))
		mod(m)
		b, _ := json.Marshal(m)
		return string(b)
	}
	exec := func(mod func(m map[string]any)) string {
		var m map[string]any
		require.NoError(t, json.Unmarshal([]byte(execArgsJSON(60, "/work", "echo", "hi")), &m))
		mod(m)
		b, _ := json.Marshal(m)
		return string(b)
	}
	for _, c := range []tc{
		{"create ok", EffectCreate, createArgsJSON, true},
		{"create extra field", EffectCreate, create(func(m map[string]any) { m["env"] = map[string]string{"A": "b"} }), false},
		{"create missing field", EffectCreate, create(func(m map[string]any) { delete(m, "memory_mb") }), false},
		{"create wrong schema", EffectCreate, create(func(m map[string]any) { m["schema"] = "helm.sandbox.exec.v1" }), false},
		{"create cpu low", EffectCreate, create(func(m map[string]any) { m["cpu_millis"] = 99 }), false},
		{"create memory high", EffectCreate, create(func(m map[string]any) { m["memory_mb"] = 65537 }), false},
		{"create timeout zero", EffectCreate, create(func(m map[string]any) { m["timeout_seconds"] = 0 }), false},
		{"create runtime with space", EffectCreate, create(func(m map[string]any) { m["runtime"] = "base image" }), false},
		{"create runtime option-like", EffectCreate, create(func(m map[string]any) { m["runtime"] = "--privileged" }), false},
		{"create egress string", EffectCreate, create(func(m map[string]any) { m["egress_disabled"] = "yes" }), false},
		{"exec ok", EffectExec, exec(func(m map[string]any) {}), true},
		{"exec empty workdir", EffectExec, exec(func(m map[string]any) { m["workdir"] = "" }), true},
		{"exec no command", EffectExec, exec(func(m map[string]any) { m["command"] = []string{} }), false},
		{"exec empty argument", EffectExec, exec(func(m map[string]any) { m["command"] = []string{"echo", ""} }), false},
		{"exec env field", EffectExec, exec(func(m map[string]any) { m["env"] = map[string]string{"TOKEN": "x"} }), false},
		{"exec relative workdir", EffectExec, exec(func(m map[string]any) { m["workdir"] = "work" }), false},
		{"exec dotdot workdir", EffectExec, exec(func(m map[string]any) { m["workdir"] = "/a/../etc" }), false},
		{"exec workdir quote", EffectExec, exec(func(m map[string]any) { m["workdir"] = "/a'b" }), false},
		{"exec timeout high", EffectExec, exec(func(m map[string]any) { m["timeout_seconds"] = 3601 }), false},
		{"terminate ok", EffectTerminate, terminateArgsJSON, true},
		{"terminate extra", EffectTerminate, `{"schema":"helm.sandbox.terminate.v1","force":true}`, false},
	} {
		run(c)
	}
}

func TestCreateDispatchesOnceLabelsTheSandboxAndReadsItBack(t *testing.T) {
	mem := newMem()
	ta := newTestAdapter(t, mem)
	creds := &staticToken{token: testKey}
	e := effectFor(EffectCreate, "sandbox/e2b", createArgsJSON, tenantA, attemptID(t))

	d := ta.Dispatch(t.Context(), creds, e, digest(createArgsJSON))
	require.Equal(t, adapters.DispatchSent, d.Status, d.Detail)
	require.Len(t, mem.specs, 1)
	assert.Equal(t, tenantLabel(tenantA), mem.specs[0].Labels[actuators.LabelTenant])
	assert.Equal(t, e.Invocation.AttemptID, mem.specs[0].Labels[actuators.LabelAttempt])
	assert.NotContains(t, mem.specs[0].Labels[actuators.LabelTenant], tenantA, "the provider never learns the tenant id")
	assert.Equal(t, int64(256), mem.specs[0].Resources.MemoryMB)
	assert.True(t, mem.specs[0].Egress.Disabled)

	// A second dispatch of the same attempt finds the sandbox and creates none.
	d = ta.Dispatch(t.Context(), creds, e, digest(createArgsJSON))
	assert.Equal(t, adapters.DispatchSent, d.Status)
	assert.Equal(t, 1, mem.createCalls, "a repeated dispatch must not create a second sandbox")

	o := ta.Observe(t.Context(), creds, e)
	require.Equal(t, adapters.OutcomeSucceeded, o.Outcome, o.Detail)
	assert.Equal(t, trustProvider, o.Observation.TrustClass)
	art := artifactOf(t, o.Observation)
	assert.Equal(t, "running", art["state"])
	assert.Equal(t, "e2b", art["provider"])
	assert.Equal(t, "sbx-1", art["sandbox_id"])
	decl, _ := ta.declaration(EffectCreate)
	schema, err := adapters.CompileResultSchema(decl)
	require.NoError(t, err)
	assert.NoError(t, schema.Validate(o.Observation.Artifact), "the established result satisfies the declared schema")
	assert.Len(t, o.Observation.EvidenceDigest, 32)
	assert.Equal(t, creds.token, testKey)
}

func TestCreateNotSentVersusIndefinite(t *testing.T) {
	refused := &actuators.CallError{Provider: "e2b", Status: 422, Refused: true, Detail: "POST /sandboxes: status 422"}
	for name, tc := range map[string]struct {
		prepare func(m *memProvider)
		want    adapters.DispatchStatus
		reason  contracts.ReasonCode
	}{
		"provider refuses the write (4xx)": {func(m *memProvider) { m.createErr = refused }, adapters.DispatchNotSent, contracts.ReasonProviderError},
		"credential rejected (401)": {func(m *memProvider) {
			m.createErr = &actuators.CallError{Provider: "e2b", Status: 401, Refused: true, Detail: "x"}
		}, adapters.DispatchNotSent, contracts.ReasonProviderCredentialRejected},
		"preflight fails":             {func(m *memProvider) { m.createErr = actuators.ErrPreflightFailed }, adapters.DispatchNotSent, contracts.ReasonProviderError},
		"read before the write fails": {func(m *memProvider) { m.findErr = errors.New("connection refused") }, adapters.DispatchNotSent, contracts.ReasonProviderError},
		"server error (5xx)":          {func(m *memProvider) { m.createErr = &actuators.CallError{Provider: "e2b", Status: 503, Detail: "x"} }, adapters.DispatchIndefinite, contracts.ReasonProviderError},
		"transport failure":           {func(m *memProvider) { m.createErr = errors.New("connection reset") }, adapters.DispatchIndefinite, contracts.ReasonProviderError},
		"request timeout (408) is not a no": {func(m *memProvider) {
			m.createErr = &actuators.CallError{Provider: "e2b", Status: 408, Refused: true, Detail: "x"}
		}, adapters.DispatchIndefinite, contracts.ReasonProviderError},
		"answer of the wrong shape": {func(m *memProvider) {
			m.createErr = &actuators.CallError{Provider: "e2b", Status: 200, Drift: true, Detail: "x"}
		}, adapters.DispatchIndefinite, contracts.ReasonConnectorContractDrift},
		"answer too large": {func(m *memProvider) {
			m.createErr = &actuators.CallError{Provider: "e2b", Status: 200, TooLarge: true, Detail: "x"}
		}, adapters.DispatchIndefinite, contracts.ReasonProviderResponseTooLarge},
		"success with an unusable sandbox id": {func(m *memProvider) { m.createID = "../escape" }, adapters.DispatchIndefinite, contracts.ReasonConnectorContractDrift},
	} {
		t.Run(name, func(t *testing.T) {
			mem := newMem()
			tc.prepare(mem)
			ta := newTestAdapter(t, mem)
			e := effectFor(EffectCreate, "sandbox/e2b", createArgsJSON, tenantA, attemptID(t))
			d := ta.Dispatch(t.Context(), &staticToken{token: testKey}, e, digest(createArgsJSON))
			assert.Equal(t, tc.want, d.Status, d.Detail)
			assert.Equal(t, tc.reason, d.Reason)
			assert.NotContains(t, d.Detail, testKey)
		})
	}
}

func TestAnIndefiniteCreateIsReconciledByReadBack(t *testing.T) {
	// The provider created the sandbox and the answer was lost: the write
	// landed, the dispatch is INDEFINITE, and Observe finds it by its label.
	mem := newMem()
	mem.createErr, mem.landThenFail = &actuators.CallError{Provider: "e2b", Status: 502, Detail: "POST /sandboxes: status 502"}, true
	ta := newTestAdapter(t, mem)
	creds := &staticToken{token: testKey}
	e := effectFor(EffectCreate, "sandbox/e2b", createArgsJSON, tenantA, attemptID(t))
	d := ta.Dispatch(t.Context(), creds, e, digest(createArgsJSON))
	require.Equal(t, adapters.DispatchIndefinite, d.Status)
	o := ta.Observe(t.Context(), creds, e)
	require.Equal(t, adapters.OutcomeSucceeded, o.Outcome, o.Detail)
	assert.Equal(t, "sbx-1", artifactOf(t, o.Observation)["sandbox_id"])

	// And when the write did not land, the read-back says absent, which the
	// gateway takes as inconclusive until the dispatch fence has passed.
	mem2 := newMem()
	ta2 := newTestAdapter(t, mem2)
	o = ta2.Observe(t.Context(), creds, effectFor(EffectCreate, "sandbox/e2b", createArgsJSON, tenantA, attemptID(t)))
	assert.Equal(t, adapters.OutcomeFailed, o.Outcome)
	assert.True(t, o.Absent)
	assert.Equal(t, contracts.ReasonReadbackMismatch, o.Reason)
	assert.Equal(t, "absent", artifactOf(t, o.Observation)["state"])
}

func TestCreateReadBackStates(t *testing.T) {
	for name, tc := range map[string]struct {
		status  actuators.SandboxStatus
		runtime string
		want    adapters.Outcome
	}{
		"running":                  {actuators.StatusRunning, "base", adapters.OutcomeSucceeded},
		"still creating":           {actuators.StatusCreating, "base", adapters.OutcomeUnknown},
		"terminated already":       {actuators.StatusTerminated, "base", adapters.OutcomeFailed},
		"errored":                  {actuators.StatusError, "base", adapters.OutcomeFailed},
		"another runtime reported": {actuators.StatusRunning, "other", adapters.OutcomeFailed},
		"unknown state":            {actuators.SandboxStatus("weird"), "base", adapters.OutcomeUnknown},
	} {
		t.Run(name, func(t *testing.T) {
			mem := newMem()
			ta := newTestAdapter(t, mem)
			att := attemptID(t)
			mem.sandboxes["sbx-9"] = &actuators.Info{ID: "sbx-9", Status: tc.status, Runtime: tc.runtime,
				Labels: map[string]string{actuators.LabelTenant: tenantLabel(tenantA), actuators.LabelAttempt: att}}
			o := ta.Observe(t.Context(), &staticToken{token: testKey}, effectFor(EffectCreate, "sandbox/e2b", createArgsJSON, tenantA, att))
			assert.Equal(t, tc.want, o.Outcome, o.Detail)
			if tc.want == adapters.OutcomeUnknown {
				assert.Nil(t, o.Observation)
			}
		})
	}
	t.Run("two sandboxes carry the label", func(t *testing.T) {
		mem := newMem()
		ta := newTestAdapter(t, mem)
		att := attemptID(t)
		labels := map[string]string{actuators.LabelTenant: tenantLabel(tenantA), actuators.LabelAttempt: att}
		mem.adopt("sbx-1", labels)
		mem.adopt("sbx-2", labels)
		o := ta.Observe(t.Context(), &staticToken{token: testKey}, effectFor(EffectCreate, "sandbox/e2b", createArgsJSON, tenantA, att))
		assert.Equal(t, adapters.OutcomeFailed, o.Outcome)
		assert.False(t, o.Absent, "an ambiguous answer is not an absence")
		assert.Equal(t, "ambiguous", artifactOf(t, o.Observation)["state"])
		d := ta.Dispatch(t.Context(), &staticToken{token: testKey}, effectFor(EffectCreate, "sandbox/e2b", createArgsJSON, tenantA, att), digest(createArgsJSON))
		assert.Equal(t, adapters.DispatchNotSent, d.Status)
		assert.Zero(t, mem.createCalls)
	})
	t.Run("a listing that ignores the labels asked for", func(t *testing.T) {
		mem := newMem()
		ta := newTestAdapter(t, mem)
		att := attemptID(t)
		mem.sandboxes["x"] = &actuators.Info{ID: "x", Status: actuators.StatusRunning, Labels: map[string]string{}}
		// A provider that returns a foreign sandbox from Find is a contract
		// drift, never a result.
		bad := &listsEverything{memProvider: mem}
		ta.backends["e2b"] = Backend{Name: "e2b", NeedsKey: true, ValidateRuntime: testValidate,
			Open: func(ctx context.Context, _ string) (actuators.Provider, context.Context, error) {
				return bad, ctx, nil
			}}
		o := ta.Observe(t.Context(), &staticToken{token: testKey}, effectFor(EffectCreate, "sandbox/e2b", createArgsJSON, tenantA, att))
		assert.Equal(t, adapters.OutcomeUnknown, o.Outcome)
		assert.Equal(t, contracts.ReasonConnectorContractDrift, o.Reason)
	})
}

// listsEverything is a provider whose Find ignores its filter.
type listsEverything struct{ *memProvider }

func (l *listsEverything) Find(context.Context, map[string]string) ([]actuators.Info, error) {
	var out []actuators.Info
	for _, s := range l.sandboxes {
		out = append(out, *s)
	}
	return out, nil
}

func TestExecRunsTheCommandOnceAndReadsItsRecordBack(t *testing.T) {
	mem := newMem()
	ta := newTestAdapter(t, mem)
	creds := &staticToken{token: testKey}
	id := createSandbox(t, ta, tenantA)
	target := "sandbox/e2b/" + id
	att := attemptID(t)

	// Argument characters that a shell would interpret stay literal: the
	// command is an argument vector, not a string.
	args := execArgsJSON(60, "", "sh", "-c", `printf '%s|%s' "$0" "$1"; echo err >&2; exit 7`, `a b; touch /tmp/pwned-`+att, `$(id)`)
	e := effectFor(EffectExec, target, args, tenantA, att)
	d := ta.Dispatch(t.Context(), creds, e, digest(args))
	require.Equal(t, adapters.DispatchSent, d.Status, d.Detail)
	assert.Equal(t, 1, mem.execCalls, "exactly one exec carries the command")

	// A second dispatch of the same attempt must not run the command again.
	before := mem.execCalls
	d = ta.Dispatch(t.Context(), creds, e, digest(args))
	require.Equal(t, adapters.DispatchSent, d.Status, d.Detail)
	o := ta.Observe(t.Context(), creds, e)
	require.Equal(t, adapters.OutcomeSucceeded, o.Outcome, o.Detail)
	assert.Equal(t, trustSandbox, o.Observation.TrustClass)
	art := artifactOf(t, o.Observation)
	assert.EqualValues(t, 7, art["exit_code"])
	assert.Equal(t, "completed", art["state"])
	assert.Equal(t, "a b; touch /tmp/pwned-"+att+"|$(id)", art["stdout_excerpt"])
	assert.Equal(t, "err\n", art["stderr_excerpt"])
	assert.EqualValues(t, len(art["stdout_excerpt"].(string)), art["stdout_bytes"])
	assert.Equal(t, false, art["stdout_truncated"])
	decl, _ := ta.declaration(EffectExec)
	schema, err := adapters.CompileResultSchema(decl)
	require.NoError(t, err)
	assert.NoError(t, schema.Validate(o.Observation.Artifact))
	// The wrapper did not start twice: the second dispatch ran only the
	// wrapper, which saw the started marker and exited.
	assert.Equal(t, before+1+3, mem.execCalls, "second dispatch + status + stdout + stderr reads")
	_, statErr := os.Stat("/tmp/pwned-" + att)
	assert.Error(t, statErr, "the command's arguments were never interpreted by a shell")
}

func TestExecRecordLargeOutputIsBoundedAndWorkdirIsUsed(t *testing.T) {
	mem := newMem()
	ta := newTestAdapter(t, mem)
	creds := &staticToken{token: testKey}
	id := createSandbox(t, ta, tenantA)
	att := attemptID(t)
	args := execArgsJSON(60, "/tmp", "sh", "-c", `pwd; i=0; while [ $i -lt 3000 ]; do printf 'abcdefghij'; i=$((i+1)); done`)
	e := effectFor(EffectExec, "sandbox/e2b/"+id, args, tenantA, att)
	require.Equal(t, adapters.DispatchSent, ta.Dispatch(t.Context(), creds, e, digest(args)).Status)
	o := ta.Observe(t.Context(), creds, e)
	require.Equal(t, adapters.OutcomeSucceeded, o.Outcome, o.Detail)
	art := artifactOf(t, o.Observation)
	assert.Equal(t, true, art["stdout_truncated"])
	assert.Len(t, art["stdout_excerpt"], excerptBytes)
	excerpt := art["stdout_excerpt"].(string)
	firstLine := excerpt[:strings.Index(excerpt, "\n")+1]
	assert.True(t, firstLine == "/tmp\n" || firstLine == "/private/tmp\n", "the command ran in the requested directory, got %q", firstLine)
	assert.EqualValues(t, 30000+len(firstLine), art["stdout_bytes"], "the size is the whole output's, not the excerpt's")
}

func TestExecReadBackWhileTheCommandRunsAndAfterItsTimeout(t *testing.T) {
	mem := newMem()
	ta := newTestAdapter(t, mem)
	creds := &staticToken{token: testKey}
	id := createSandbox(t, ta, tenantA)
	att := attemptID(t)
	args := execArgsJSON(60, "", "true")
	e := effectFor(EffectExec, "sandbox/e2b/"+id, args, tenantA, att)

	// Nothing recorded: the command never started.
	o := ta.Observe(t.Context(), creds, e)
	assert.Equal(t, adapters.OutcomeFailed, o.Outcome)
	assert.True(t, o.Absent)
	assert.Equal(t, "not_started", artifactOf(t, o.Observation)["state"])

	// Started, not finished, inside its timeout: inconclusive.
	mem.execResult = func(argv []string) (*actuators.ExecResult, bool) {
		if len(argv) > 3 && argv[3] == "helm-status" {
			return &actuators.ExecResult{Stdout: []byte("running 1000 1030\n")}, true
		}
		return nil, false
	}
	o = ta.Observe(t.Context(), creds, e)
	assert.Equal(t, adapters.OutcomeUnknown, o.Outcome)
	assert.Nil(t, o.Observation)

	// Started and past its timeout plus the grace: the command was cut off.
	mem.execResult = func(argv []string) (*actuators.ExecResult, bool) {
		if len(argv) > 3 && argv[3] == "helm-status" {
			return &actuators.ExecResult{Stdout: []byte("running 1000 1091\n")}, true
		}
		return nil, false
	}
	o = ta.Observe(t.Context(), creds, e)
	require.Equal(t, adapters.OutcomeSucceeded, o.Outcome, o.Detail)
	art := artifactOf(t, o.Observation)
	assert.Equal(t, "timed_out", art["state"])
	assert.EqualValues(t, -1, art["exit_code"])

	// A malformed record is inconclusive, never a verdict.
	mem.execResult = func(argv []string) (*actuators.ExecResult, bool) {
		if len(argv) > 3 && argv[3] == "helm-status" {
			return &actuators.ExecResult{Stdout: []byte("done 300 5 5\n")}, true
		}
		return nil, false
	}
	o = ta.Observe(t.Context(), creds, e)
	assert.Equal(t, adapters.OutcomeUnknown, o.Outcome)
	assert.Equal(t, contracts.ReasonConnectorContractDrift, o.Reason)
}

func TestExecDispatchClassification(t *testing.T) {
	for name, tc := range map[string]struct {
		hook func(argv []string) (*actuators.ExecResult, bool)
		err  error
		want adapters.DispatchStatus
	}{
		"wrapper could not write its record": {hook: exitWith(125), want: adapters.DispatchNotSent},
		"no shell in the sandbox":            {hook: exitWith(127), want: adapters.DispatchNotSent},
		"wrapper killed":                     {hook: exitWith(137), want: adapters.DispatchIndefinite},
		"provider timeout":                   {hook: func([]string) (*actuators.ExecResult, bool) { return &actuators.ExecResult{TimedOut: true}, true }, want: adapters.DispatchIndefinite},
		"provider refuses (4xx)":             {err: &actuators.CallError{Provider: "e2b", Status: 404, Refused: true, Detail: "x"}, want: adapters.DispatchNotSent},
		"provider fails (5xx)":               {err: &actuators.CallError{Provider: "e2b", Status: 500, Detail: "x"}, want: adapters.DispatchIndefinite},
		"connection lost":                    {err: errors.New("EOF"), want: adapters.DispatchIndefinite},
	} {
		t.Run(name, func(t *testing.T) {
			mem := newMem()
			ta := newTestAdapter(t, mem)
			creds := &staticToken{token: testKey}
			id := createSandbox(t, ta, tenantA)
			mem.execResult, mem.execErr = tc.hook, tc.err
			args := execArgsJSON(60, "", "true")
			d := ta.Dispatch(t.Context(), creds, effectFor(EffectExec, "sandbox/e2b/"+id, args, tenantA, attemptID(t)), digest(args))
			assert.Equal(t, tc.want, d.Status, d.Detail)
		})
	}
}

func exitWith(code int) func([]string) (*actuators.ExecResult, bool) {
	return func([]string) (*actuators.ExecResult, bool) { return &actuators.ExecResult{ExitCode: code}, true }
}

func TestATenantReachesOnlyItsOwnSandboxes(t *testing.T) {
	mem := newMem()
	ta := newTestAdapter(t, mem)
	creds := &staticToken{token: testKey}
	mine := createSandbox(t, ta, tenantA)
	// One the gateway did not create (no labels), and one another tenant did.
	mem.adopt("foreign-1", nil)
	mem.adopt("foreign-2", map[string]string{actuators.LabelTenant: tenantLabel(tenantB), actuators.LabelAttempt: "x"})

	args := execArgsJSON(60, "", "true")
	for _, id := range []string{"foreign-1", "foreign-2", "missing-1"} {
		execCallsBefore := mem.execCalls
		for effectType, a := range map[string]string{EffectExec: args, EffectTerminate: terminateArgsJSON} {
			e := effectFor(effectType, "sandbox/e2b/"+id, a, tenantA, attemptID(t))
			d := ta.Dispatch(t.Context(), creds, e, digest(a))
			assert.Equal(t, adapters.DispatchNotSent, d.Status, "%s on %s", effectType, id)
			assert.Equal(t, contracts.ReasonPreconditionFailed, d.Reason)
			assert.NotContains(t, d.Detail, tenantLabel(tenantB), "a refusal does not reveal another tenant's sandbox")
			if effectType == EffectExec {
				o := ta.Observe(t.Context(), creds, e)
				assert.Equal(t, adapters.OutcomeUnknown, o.Outcome, "the read-back never reads a sandbox that is not this tenant's")
			}
		}
		assert.Equal(t, execCallsBefore, mem.execCalls, "no command ran in %s", id)
	}
	assert.Zero(t, mem.terminateCalls)
	// The owner still can.
	e := effectFor(EffectExec, "sandbox/e2b/"+mine, args, tenantA, attemptID(t))
	assert.Equal(t, adapters.DispatchSent, ta.Dispatch(t.Context(), creds, e, digest(args)).Status)
	// And the same sandbox is foreign to the other tenant.
	e = effectFor(EffectExec, "sandbox/e2b/"+mine, args, tenantB, attemptID(t))
	assert.Equal(t, adapters.DispatchNotSent, ta.Dispatch(t.Context(), creds, e, digest(args)).Status)
}

func TestExecOnASandboxThatIsNotRunning(t *testing.T) {
	mem := newMem()
	ta := newTestAdapter(t, mem)
	id := createSandbox(t, ta, tenantA)
	mem.sandboxes[id].Status = actuators.StatusPaused
	args := execArgsJSON(60, "", "true")
	d := ta.Dispatch(t.Context(), &staticToken{token: testKey}, effectFor(EffectExec, "sandbox/e2b/"+id, args, tenantA, attemptID(t)), digest(args))
	assert.Equal(t, adapters.DispatchNotSent, d.Status)
	assert.Equal(t, contracts.ReasonPreconditionFailed, d.Reason)
}

func TestTerminateAndItsReadBack(t *testing.T) {
	mem := newMem()
	ta := newTestAdapter(t, mem)
	creds := &staticToken{token: testKey}
	id := createSandbox(t, ta, tenantA)
	e := effectFor(EffectTerminate, "sandbox/e2b/"+id, terminateArgsJSON, tenantA, attemptID(t))
	d := ta.Dispatch(t.Context(), creds, e, digest(terminateArgsJSON))
	require.Equal(t, adapters.DispatchSent, d.Status, d.Detail)
	o := ta.Observe(t.Context(), creds, e)
	require.Equal(t, adapters.OutcomeSucceeded, o.Outcome, o.Detail)
	assert.Equal(t, "terminated", artifactOf(t, o.Observation)["state"])
	decl, _ := ta.declaration(EffectTerminate)
	schema, _ := adapters.CompileResultSchema(decl)
	assert.NoError(t, schema.Validate(o.Observation.Artifact))

	// A sandbox the provider has dropped entirely is terminated too.
	delete(mem.sandboxes, id)
	o = ta.Observe(t.Context(), creds, e)
	assert.Equal(t, adapters.OutcomeSucceeded, o.Outcome, o.Detail)

	// Terminating an already terminated sandbox is refused up front.
	mem.adopt("dead", map[string]string{actuators.LabelTenant: tenantLabel(tenantA)})
	mem.sandboxes["dead"].Status = actuators.StatusTerminated
	d = ta.Dispatch(t.Context(), creds, effectFor(EffectTerminate, "sandbox/e2b/dead", terminateArgsJSON, tenantA, attemptID(t)), digest(terminateArgsJSON))
	assert.Equal(t, adapters.DispatchNotSent, d.Status)

	// A sandbox that is still running after the terminate is inconclusive.
	still := createSandbox(t, ta, tenantA)
	mem.terminateErr = nil
	e = effectFor(EffectTerminate, "sandbox/e2b/"+still, terminateArgsJSON, tenantA, attemptID(t))
	o = ta.Observe(t.Context(), creds, e)
	assert.Equal(t, adapters.OutcomeUnknown, o.Outcome)

	// A terminate the provider refuses did not happen; one it fails may have.
	mem.terminateErr = &actuators.CallError{Provider: "e2b", Status: 409, Refused: true, Detail: "x"}
	assert.Equal(t, adapters.DispatchNotSent, ta.Dispatch(t.Context(), creds, e, digest(terminateArgsJSON)).Status)
	mem.terminateErr = &actuators.CallError{Provider: "e2b", Status: 500, Detail: "x"}
	assert.Equal(t, adapters.DispatchIndefinite, ta.Dispatch(t.Context(), creds, e, digest(terminateArgsJSON)).Status)
}

func TestDispatchComparesTheArgumentDigestBeforeAnyProviderCall(t *testing.T) {
	mem := newMem()
	ta := newTestAdapter(t, mem)
	creds := &staticToken{token: testKey}
	e := effectFor(EffectCreate, "sandbox/e2b", createArgsJSON, tenantA, attemptID(t))
	d := ta.Dispatch(t.Context(), creds, e, digest(strings.Replace(createArgsJSON, "256", "257", 1)))
	assert.Equal(t, adapters.DispatchNotSent, d.Status)
	assert.Equal(t, contracts.ReasonPermitArgumentMismatch, d.Reason)
	d = ta.Dispatch(t.Context(), creds, e, nil)
	assert.Equal(t, adapters.DispatchNotSent, d.Status)
	assert.Zero(t, ta.opens, "no provider was opened")
	assert.Zero(t, creds.calls, "no credential was asked for")
	assert.Zero(t, mem.createCalls)
}

func TestTargetsComeOnlyFromTheTarget(t *testing.T) {
	mem := newMem()
	ta := newTestAdapter(t, mem)
	creds := &staticToken{token: testKey}
	for name, tc := range map[string]struct{ effectType, target, args string }{
		"unknown provider":       {EffectCreate, "sandbox/nope", createArgsJSON},
		"unconfigured provider":  {EffectCreate, "sandbox/daytona", createArgsJSON},
		"create names a sandbox": {EffectCreate, "sandbox/e2b/sbx-1", createArgsJSON},
		"exec names none":        {EffectExec, "sandbox/e2b", execArgsJSON(5, "", "true")},
		"path in the id":         {EffectExec, "sandbox/e2b/../x", execArgsJSON(5, "", "true")},
		"url target":             {EffectCreate, "https://api.e2b.dev", createArgsJSON},
	} {
		t.Run(name, func(t *testing.T) {
			d := ta.Dispatch(t.Context(), creds, effectFor(tc.effectType, tc.target, tc.args, tenantA, attemptID(t)), digest(tc.args))
			assert.Equal(t, adapters.DispatchNotSent, d.Status)
		})
	}
	assert.Zero(t, mem.createCalls)
	assert.Zero(t, ta.opens)
}

func TestACredentialIsAskedForPerCallAndNeverLeavesTheProviderClient(t *testing.T) {
	mem := newMem()
	ta := newTestAdapter(t, mem)
	creds := &staticToken{token: testKey}
	id := createSandbox(t, ta, tenantA)
	args := execArgsJSON(60, "", "echo", "hello")
	att := attemptID(t)
	e := effectFor(EffectExec, "sandbox/e2b/"+id, args, tenantA, att)
	require.Equal(t, adapters.DispatchSent, ta.Dispatch(t.Context(), creds, e, digest(args)).Status)
	o := ta.Observe(t.Context(), creds, e)
	require.Equal(t, adapters.OutcomeSucceeded, o.Outcome)

	// The key reached only the provider constructor.
	for _, opened := range ta.opened {
		assert.Equal(t, testKey, opened)
	}
	everything, _ := json.Marshal(struct {
		Specs []*actuators.SandboxSpec
		Argv  [][]string
		Obs   *adapters.Observation
		O     adapters.ObserveResult
	}{mem.specs, mem.argv, o.Observation, o})
	assert.NotContains(t, string(everything), testKey, "no spec, command or result carries the provider key")
	assert.NotContains(t, fmt.Sprint(ta.Declarations()), testKey)

	// No key, no dispatch.
	none := &staticToken{err: errors.New("no key for e2b")}
	d := ta.Dispatch(t.Context(), none, effectFor(EffectCreate, "sandbox/e2b", createArgsJSON, tenantA, attemptID(t)), digest(createArgsJSON))
	assert.Equal(t, adapters.DispatchNotSent, d.Status)
	assert.Equal(t, contracts.ReasonProviderCredentialRejected, d.Reason)
	d = ta.Dispatch(t.Context(), nil, effectFor(EffectCreate, "sandbox/e2b", createArgsJSON, tenantA, attemptID(t)), digest(createArgsJSON))
	assert.Equal(t, adapters.DispatchNotSent, d.Status)
}

func TestAKeylessProviderIsNeverAskedForACredential(t *testing.T) {
	mem := newMem()
	a, err := New([]Backend{{Name: "docker", ValidateRuntime: func(string) error { return nil },
		Open: func(ctx context.Context, token string) (actuators.Provider, context.Context, error) {
			assert.Empty(t, token)
			return mem, ctx, nil
		}}})
	require.NoError(t, err)
	creds := &staticToken{token: "must-not-be-read"}
	e := effectFor(EffectCreate, "sandbox/docker", createArgsJSON, tenantA, attemptID(t))
	d := a.Dispatch(t.Context(), creds, e, digest(createArgsJSON))
	assert.Equal(t, adapters.DispatchSent, d.Status, d.Detail)
	assert.Zero(t, creds.calls)
}

func TestAnEffectWithoutAnInvocationDoesNotDispatch(t *testing.T) {
	mem := newMem()
	ta := newTestAdapter(t, mem)
	e := adapters.Effect{EffectType: EffectCreate, Target: "sandbox/e2b", Arguments: []byte(createArgsJSON)}
	d := ta.Dispatch(t.Context(), &staticToken{token: testKey}, e, digest(createArgsJSON))
	assert.Equal(t, adapters.DispatchNotSent, d.Status)
	assert.Zero(t, mem.createCalls)
	o := ta.Observe(t.Context(), &staticToken{token: testKey}, e)
	assert.Equal(t, adapters.OutcomeUnknown, o.Outcome)
}

func TestPrepareValidatesAndChangesNothing(t *testing.T) {
	mem := newMem()
	ta := newTestAdapter(t, mem)
	creds := &staticToken{token: testKey}
	p, err := ta.Prepare(t.Context(), creds, adapters.Effect{EffectType: EffectCreate, Target: "sandbox/e2b", Arguments: []byte(createArgsJSON)})
	require.NoError(t, err)
	assert.Equal(t, "e2b", p.Resolved["provider"])
	_, err = ta.Prepare(t.Context(), creds, adapters.Effect{EffectType: EffectCreate, Target: "sandbox/e2b", Arguments: []byte(`{}`)})
	var refusal *adapters.Refusal
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, contracts.ReasonSchemaViolation, refusal.Reason)
	_, err = ta.Prepare(t.Context(), creds, adapters.Effect{EffectType: "github.git.push", Target: "x", Arguments: []byte(`{}`)})
	require.Error(t, err)
	id := createSandbox(t, ta, tenantA)
	_, err = ta.Prepare(t.Context(), creds, effectFor(EffectTerminate, "sandbox/e2b/"+id, terminateArgsJSON, tenantB, "a1"))
	require.Error(t, err, "another tenant's sandbox is not preparable")
	assert.Zero(t, mem.terminateCalls)
}

func TestNewRefusesAnUnusableConfiguration(t *testing.T) {
	open := func(ctx context.Context, _ string) (actuators.Provider, context.Context, error) {
		return nil, ctx, nil
	}
	ok := func(string) error { return nil }
	_, err := New(nil)
	assert.Error(t, err)
	_, err = New([]Backend{{Name: "other", Open: open, ValidateRuntime: ok}})
	assert.Error(t, err)
	_, err = New([]Backend{{Name: "e2b"}})
	assert.Error(t, err)
	_, err = New([]Backend{{Name: "e2b", Open: open, ValidateRuntime: ok}, {Name: "e2b", Open: open, ValidateRuntime: ok}})
	assert.Error(t, err)
}

func TestExecDoesNotStartTwiceForOneAttempt(t *testing.T) {
	mem := newMem()
	ta := newTestAdapter(t, mem)
	creds := &staticToken{token: testKey}
	id := createSandbox(t, ta, tenantA)
	att := attemptID(t)
	counter := recordDir(att) + ".count"
	t.Cleanup(func() { _ = os.Remove(counter) })
	args := execArgsJSON(60, "", "sh", "-c", `echo run >> "$0"`, counter)
	e := effectFor(EffectExec, "sandbox/e2b/"+id, args, tenantA, att)
	for i := 0; i < 3; i++ {
		require.Equal(t, adapters.DispatchSent, ta.Dispatch(t.Context(), creds, e, digest(args)).Status)
	}
	raw, err := os.ReadFile(counter)
	require.NoError(t, err)
	assert.Equal(t, "run\n", string(raw), "the command started once for the attempt, however often it was dispatched")
}
