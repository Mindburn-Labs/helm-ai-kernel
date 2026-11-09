package sandbox

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/actuators"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
)

// ── results of Dispatch and Observe ────────────────────────────────────

func notSent(r *adapters.Refusal) adapters.DispatchResult {
	return adapters.DispatchResult{Status: adapters.DispatchNotSent, Reason: r.Reason, Detail: r.Detail}
}

func indefinite(reason contracts.ReasonCode, format string, args ...any) adapters.DispatchResult {
	return adapters.DispatchResult{Status: adapters.DispatchIndefinite, Reason: reason, Detail: fmt.Sprintf(format, args...)}
}

func sent(detail string) adapters.DispatchResult {
	return adapters.DispatchResult{Status: adapters.DispatchSent, Detail: detail}
}

func unknown(r *adapters.Refusal) adapters.ObserveResult {
	return adapters.ObserveResult{Outcome: adapters.OutcomeUnknown, Reason: r.Reason, Detail: r.Detail}
}

// providerRefusal classifies a failed provider READ (or a write refused
// before it was sent) as a refusal.
func providerRefusal(err error) *adapters.Refusal {
	if ce := actuators.AsCallError(err); ce != nil {
		switch {
		case ce.Drift:
			return adapters.Refuse(contracts.ReasonConnectorContractDrift, "%s", describe(err))
		case ce.TooLarge:
			return adapters.Refuse(contracts.ReasonProviderResponseTooLarge, "%s", describe(err))
		case ce.Status == http.StatusUnauthorized || ce.Status == http.StatusForbidden:
			return adapters.Refuse(contracts.ReasonProviderCredentialRejected, "%s", describe(err))
		}
	}
	return adapters.Refuse(contracts.ReasonProviderError, "%s", describe(err))
}

// writeFailure classifies the failure of the effect's one write. It is
// NOT_SENT only when the write certainly did not happen: the provider or the
// adapter refused it before acting (a 4xx other than a request timeout, a failed
// preflight, an unknown sandbox, an operation the provider lacks). A transport
// error, a 5xx, a timeout, an answer too large or of the wrong shape may all
// follow a write that took effect, so they are INDEFINITE and Observe decides.
func writeFailure(err error) adapters.DispatchResult {
	switch {
	case errors.Is(err, actuators.ErrPreflightFailed), errors.Is(err, actuators.ErrNotSupported),
		errors.Is(err, actuators.ErrSandboxNotFound), errors.Is(err, actuators.ErrBadID):
		return notSent(providerRefusal(err))
	}
	if ce := actuators.AsCallError(err); ce != nil && ce.Refused && ce.Status != http.StatusRequestTimeout {
		return notSent(providerRefusal(err))
	}
	r := providerRefusal(err)
	return indefinite(r.Reason, "%s", r.Detail)
}

// ── artifacts ──────────────────────────────────────────────────────────

func (a *Adapter) observation(trust, schemaID string, result map[string]any, evidence any) (*adapters.Observation, error) {
	canon, err := canonicalize.InteroperableJCS(result)
	if err != nil {
		return nil, err
	}
	artifact, err := adapters.NewJSONResult(schemaID, canon)
	if err != nil {
		return nil, err
	}
	facts, err := canonicalize.JCS(evidence)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(facts)
	return &adapters.Observation{Source: observationSource, TrustClass: trust, EvidenceDigest: digest[:],
		ObservedAt: a.now().UTC(), Artifact: artifact}, nil
}

// settle is the established result of a read-back: SUCCEEDED when mismatch is
// empty, else FAILED with READBACK_MISMATCH. Both carry the observation.
func settle(obs *adapters.Observation, mismatch string, absent bool) adapters.ObserveResult {
	if mismatch == "" {
		return adapters.ObserveResult{Outcome: adapters.OutcomeSucceeded, Observation: obs}
	}
	return adapters.ObserveResult{Outcome: adapters.OutcomeFailed, Reason: contracts.ReasonReadbackMismatch,
		Detail: mismatch, Observation: obs, Absent: absent}
}

func infoFacts(infos []actuators.Info) []map[string]any {
	out := make([]map[string]any, 0, len(infos))
	for _, i := range infos {
		out = append(out, map[string]any{"id": i.ID, "status": string(i.Status), "labels": i.Labels, "runtime": i.Runtime})
	}
	sort.Slice(out, func(x, y int) bool { return fmt.Sprint(out[x]["id"]) < fmt.Sprint(out[y]["id"]) })
	return out
}

// ── sandbox.create ─────────────────────────────────────────────────────

// specOf is the provider spec a create's arguments ask for.
func specOf(args createArgs, labels map[string]string) *actuators.SandboxSpec {
	return &actuators.SandboxSpec{
		Runtime: args.Runtime,
		Resources: actuators.ResourceSpec{CPUMillis: args.CPUMillis, MemoryMB: args.MemoryMB, DiskMB: args.DiskMB,
			Timeout: time.Duration(args.TimeoutSeconds) * time.Second, MaxProcesses: int(args.MaxProcesses)},
		Egress: actuators.EgressPolicy{Disabled: args.EgressDisabled},
		Labels: labels,
	}
}

func (o *op) dispatchCreate(args createArgs) adapters.DispatchResult {
	if err := o.backend.ValidateRuntime(args.Runtime); err != nil {
		return notSent(adapters.Refuse(contracts.ReasonPreconditionFailed, "runtime: %s", describe(err)))
	}
	spec := specOf(args, o.labels())
	if err := o.backend.checkSpec(spec); err != nil {
		return notSent(adapters.Refuse(contracts.ReasonPreconditionFailed, "%s", describe(err)))
	}
	// Nothing is written yet, so a failed read is a certain NOT_SENT.
	found, err := o.provider.Find(o.ctx, o.labels())
	if err != nil {
		return notSent(providerRefusal(err))
	}
	switch {
	case len(found) == 1:
		return sent("a sandbox carrying this attempt's label already exists and was not created again; Observe decides whether it is this effect")
	case len(found) > 1:
		return notSent(adapters.Refuse(contracts.ReasonPreconditionFailed, "%d sandboxes already carry this attempt's label", len(found)))
	}
	h, err := o.provider.Create(o.ctx, spec)
	if err != nil {
		return writeFailure(err)
	}
	if h == nil || !actuators.ValidID(h.ID) {
		return indefinite(contracts.ReasonConnectorContractDrift, "the provider's create answer names no usable sandbox id")
	}
	return sent("")
}

func (o *op) observeCreate(a *Adapter, args createArgs) adapters.ObserveResult {
	found, err := o.provider.Find(o.ctx, o.labels())
	if err != nil {
		return unknown(providerRefusal(err))
	}
	result := map[string]any{"provider": o.name, "sandbox_id": "", "state": "absent", "runtime": ""}
	var info actuators.Info
	switch {
	case len(found) == 0:
	case len(found) > 1:
		result["state"] = "ambiguous"
	default:
		info = found[0]
		if info.Labels[actuators.LabelTenant] != o.tenant || info.Labels[actuators.LabelAttempt] != o.attempt || !actuators.ValidID(info.ID) {
			return unknown(adapters.Refuse(contracts.ReasonConnectorContractDrift, "the provider listed a sandbox that does not carry the labels asked for"))
		}
		result["sandbox_id"], result["state"], result["runtime"] = info.ID, string(info.Status), info.Runtime
	}
	state, _ := result["state"].(string)
	switch state {
	case "absent", "ambiguous", string(actuators.StatusRunning), string(actuators.StatusCreating), string(actuators.StatusPaused),
		string(actuators.StatusTerminated), string(actuators.StatusError):
	default:
		return unknown(adapters.Refuse(contracts.ReasonConnectorContractDrift, "the provider reports sandbox state %q", state))
	}
	if len(info.Runtime) > 256 {
		return unknown(adapters.Refuse(contracts.ReasonConnectorContractDrift, "the provider reports a runtime longer than 256 bytes"))
	}
	obs, err := a.observation(o.backend.readBackTrust(), createResultID, result, infoFacts(found))
	if err != nil {
		return unknown(adapters.Refuse(contracts.ReasonConnectorContractDrift, "the read-back does not make a result: %s", describe(err)))
	}
	switch state {
	case "absent":
		return settle(obs, fmt.Sprintf("no sandbox on %s carries this attempt's label", o.name), true)
	case "ambiguous":
		return settle(obs, fmt.Sprintf("%d sandboxes on %s carry this attempt's label", len(found), o.name), false)
	case string(actuators.StatusCreating):
		return unknown(adapters.Refuse(contracts.ReasonProviderError, "the sandbox %s is still being created", info.ID))
	case string(actuators.StatusRunning):
		if o.backend.CompareRuntime && info.Runtime != "" && info.Runtime != args.Runtime {
			return settle(obs, fmt.Sprintf("the sandbox runs %q, want %q", info.Runtime, args.Runtime), false)
		}
		return settle(obs, "", false)
	}
	return settle(obs, fmt.Sprintf("the sandbox %s is %s, want running", info.ID, state), false)
}

// ── sandbox.exec ───────────────────────────────────────────────────────

func (o *op) dispatchExec(args execArgs) adapters.DispatchResult {
	info, r := o.owned()
	if r != nil {
		return notSent(r)
	}
	if info.Status != actuators.StatusRunning {
		return notSent(adapters.Refuse(contracts.ReasonPreconditionFailed, "the sandbox %s is %s, not running", o.id, info.Status))
	}
	res, err := o.provider.Exec(o.ctx, o.id, &actuators.ExecRequest{
		Command: execArgv(o.attempt, args.Workdir, args.Command),
		Timeout: time.Duration(args.TimeoutSeconds) * time.Second,
	})
	if err != nil {
		return writeFailure(err)
	}
	switch {
	case res == nil:
		return indefinite(contracts.ReasonConnectorContractDrift, "the provider answered the exec with no result")
	case res.TimedOut || res.OOMKilled:
		return indefinite(contracts.ReasonProviderError, "the sandbox's wrapper was cut off (timed out %v, out of memory %v); the record decides", res.TimedOut, res.OOMKilled)
	case res.ExitCode == 0:
		return sent("")
	case res.ExitCode == wrapperNoRecord || res.ExitCode == wrapperNoShell || res.ExitCode == wrapperNotFound:
		// The status is what the wrapper, or the provider's own exec path,
		// reported, and a provider derives it from stderr the sandbox can
		// write. It is NOT_SENT only when the sandbox's record says the
		// command never started.
		if raw, r := o.readRecord(statusArgv(o.attempt)); r == nil {
			if st, err := parseStatus(raw); err == nil && st.kind == "none" {
				return notSent(adapters.Refuse(contracts.ReasonProviderError, "the sandbox could not start the command wrapper (status %d) and holds no record of the command", res.ExitCode))
			}
		}
		return indefinite(contracts.ReasonProviderError, "the command wrapper ended with status %d and the sandbox's record does not show that the command never started", res.ExitCode)
	}
	return indefinite(contracts.ReasonProviderError, "the command wrapper ended with status %d", res.ExitCode)
}

// readRecord runs one fixed read-only script in the sandbox and returns its
// stdout.
func (o *op) readRecord(argv []string) ([]byte, *adapters.Refusal) {
	res, err := o.provider.Exec(o.ctx, o.id, &actuators.ExecRequest{Command: argv, Timeout: readTimeout})
	switch {
	case err != nil:
		return nil, providerRefusal(err)
	case res == nil:
		return nil, adapters.Refuse(contracts.ReasonConnectorContractDrift, "the provider answered a read with no result")
	case res.TimedOut || res.ExitCode != 0:
		return nil, adapters.Refuse(contracts.ReasonProviderError, "reading the sandbox's record failed (status %d)", res.ExitCode)
	}
	return res.Stdout, nil
}

func (o *op) observeExec(a *Adapter, args execArgs) adapters.ObserveResult {
	info, r := o.owned()
	if r != nil {
		return unknown(r)
	}
	if info.Status != actuators.StatusRunning {
		return unknown(adapters.Refuse(contracts.ReasonPreconditionFailed, "the sandbox %s is %s: the command's record cannot be read", o.id, info.Status))
	}
	raw, r := o.readRecord(statusArgv(o.attempt))
	if r != nil {
		return unknown(r)
	}
	st, err := parseStatus(raw)
	if err != nil {
		return unknown(adapters.Refuse(contracts.ReasonConnectorContractDrift, "%s", describe(err)))
	}
	result := map[string]any{"provider": o.name, "sandbox_id": o.id, "state": "not_started", "exit_code": 0,
		"stdout_bytes": 0, "stderr_bytes": 0, "stdout_excerpt": "", "stderr_excerpt": "", "stdout_truncated": false, "stderr_truncated": false}
	evidence := map[string]any{"record": strings.TrimSpace(string(raw))}
	switch {
	case st.kind == "none":
		// The dispatch ended SENT or INDEFINITE, so the command may have run,
		// and the record is the sandbox's own file: a command can delete it. A
		// missing record never proves the command did not run.
		return unknown(adapters.Refuse(contracts.ReasonProviderError, "the sandbox holds no record of this attempt's command; it may have run and removed its record"))
	case st.kind == "running" && !st.timedOut(args.TimeoutSeconds):
		return unknown(adapters.Refuse(contracts.ReasonProviderError, "the command has started and not finished"))
	case st.kind == "running":
		result["state"], result["exit_code"] = "timed_out", -1
	default:
		result["state"], result["exit_code"] = "completed", int(st.rc)
		for _, s := range []struct {
			stream string
			bytes  int64
		}{{"out", st.outBytes}, {"err", st.errBytes}} {
			excerpt := ""
			if s.bytes > 0 {
				body, r := o.readRecord(excerptArgv(o.attempt, s.stream))
				if r != nil {
					return unknown(r)
				}
				if len(body) > excerptBytes {
					body = body[:excerptBytes]
				}
				excerpt = strings.ToValidUTF8(string(body), "�")
			}
			name := map[string]string{"out": "stdout", "err": "stderr"}[s.stream]
			result[name+"_bytes"], result[name+"_excerpt"], result[name+"_truncated"] = s.bytes, excerpt, s.bytes > excerptBytes
			evidence[name] = excerpt
		}
	}
	obs, err := a.observation(trustSandbox, execResultID, result, evidence)
	if err != nil {
		return unknown(adapters.Refuse(contracts.ReasonConnectorContractDrift, "the read-back does not make a result: %s", describe(err)))
	}
	return settle(obs, "", false)
}

// ── sandbox.terminate ──────────────────────────────────────────────────

func (o *op) dispatchTerminate() adapters.DispatchResult {
	info, r := o.owned()
	if r != nil {
		return notSent(r)
	}
	if info.Status == actuators.StatusTerminated {
		return notSent(adapters.Refuse(contracts.ReasonPreconditionFailed, "the sandbox %s is already terminated", o.id))
	}
	if err := o.provider.Terminate(o.ctx, o.id); err != nil {
		return writeFailure(err)
	}
	return sent("")
}

func (o *op) observeTerminate(a *Adapter) adapters.ObserveResult {
	info, err := o.provider.Lookup(o.ctx, o.id)
	result := map[string]any{"provider": o.name, "sandbox_id": o.id, "state": "terminated"}
	evidence := map[string]any{"id": o.id, "found": false}
	switch {
	case errors.Is(err, actuators.ErrSandboxNotFound):
	case err != nil:
		return unknown(providerRefusal(err))
	case info == nil || info.ID != o.id || info.Labels[actuators.LabelTenant] != o.tenant:
		return unknown(adapters.Refuse(contracts.ReasonConnectorContractDrift, "the provider answered for a sandbox that is not %s of this tenant", o.id))
	default:
		evidence = map[string]any{"id": info.ID, "found": true, "status": string(info.Status), "labels": info.Labels}
		switch info.Status {
		case actuators.StatusTerminated:
		case actuators.StatusRunning, actuators.StatusPaused, actuators.StatusCreating, actuators.StatusError:
			result["state"] = string(info.Status)
		default:
			return unknown(adapters.Refuse(contracts.ReasonConnectorContractDrift, "the provider reports sandbox state %q", info.Status))
		}
	}
	obs, oerr := a.observation(o.backend.readBackTrust(), terminateResultID, result, evidence)
	if oerr != nil {
		return unknown(adapters.Refuse(contracts.ReasonConnectorContractDrift, "the read-back does not make a result: %s", describe(oerr)))
	}
	if result["state"] != "terminated" {
		return unknown(adapters.Refuse(contracts.ReasonProviderError, "the sandbox %s is still %s", o.id, result["state"]))
	}
	return settle(obs, "", false)
}
