// quantum_posture: this example runner derives spend-intent ids with SHA-256
// exactly like the kernel's inferencegateway; it implements no cryptographic
// control of its own.

// Command paired-replay drives the HELM-618 paired task set through a running
// `helm-ai-kernel spend-proxy`, one governed call per task per envelope, and
// records the capture artifacts the savings EvidencePack binds:
//
//	task_results.json  — per-task pass/fail per route (no prompt bodies:
//	                     responses are recorded as SHA-256 only)
//	parity_prerun.json — selection-set aggregation (with --write-parity)
//
// The runner is deliberately standalone (stdlib only) so a skeptic can read
// every request it makes. Pass criteria mirror the launchpad smoke's
// completion criterion (HTTP 200, finish_reason "stop", non-empty answer)
// plus the task set's deterministic content checks.
//
// Usage:
//
//	go run . --phase parity  --envelopes env-baseline,env-cand-gpt-oss-20b,... \
//	         --request-model openai-gpt-oss-120b --run-id h618 --capture ./capture
//	go run . --phase holdout --envelopes env-baseline,env-cand-gpt-oss-20b \
//	         --request-model openai-gpt-oss-120b --run-id h618 --capture ./capture
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Task is one entry in tasks.json.
type Task struct {
	TaskID string `json:"task_id"`
	Subset string `json:"subset"`
	Prompt string `json:"prompt"`
	Check  Check  `json:"check"`
}

// Check is a deterministic pass criterion over the response content.
type Check struct {
	Kind  string `json:"kind"` // contains | number | regex
	Value string `json:"value"`
}

// TaskSet is the committed task file.
type TaskSet struct {
	SchemaVersion string `json:"schema_version"`
	SourceNote    string `json:"source_note"`
	Tasks         []Task `json:"tasks"`
}

// Result mirrors evidencepack.SavingsTaskResult (kept standalone so the runner
// stays dependency-free; the schema is owned by core/pkg/evidencepack).
type Result struct {
	TaskID           string    `json:"task_id"`
	Phase            string    `json:"phase"`
	EnvelopeID       string    `json:"envelope_id"`
	RequestedModelID string    `json:"requested_model_id"`
	IdempotencyKey   string    `json:"idempotency_key"`
	SpendIntentID    string    `json:"spend_intent_id"`
	Passed           bool      `json:"passed"`
	FailureReason    string    `json:"failure_reason,omitempty"`
	HTTPStatus       int       `json:"http_status"`
	FinishReason     string    `json:"finish_reason,omitempty"`
	ResponseSHA256   string    `json:"response_sha256,omitempty"`
	CompletedAt      time.Time `json:"completed_at"`
}

// ResultsFile mirrors evidencepack.SavingsTaskResults.
type ResultsFile struct {
	SchemaVersion string   `json:"schema_version"`
	RunID         string   `json:"run_id"`
	Results       []Result `json:"results"`
}

// ParityCandidate mirrors evidencepack.SavingsParityCandidateResult.
type ParityCandidate struct {
	EnvelopeID        string `json:"envelope_id"`
	DispatchedModelID string `json:"dispatched_model_id"`
	TasksRun          int    `json:"tasks_run"`
	TasksPassed       int    `json:"tasks_passed"`
}

// ParityFile mirrors evidencepack.SavingsParityResults.
type ParityFile struct {
	SchemaVersion    string            `json:"schema_version"`
	RunID            string            `json:"run_id"`
	SelectionTaskIDs []string          `json:"selection_task_ids"`
	Baseline         ParityCandidate   `json:"baseline"`
	Candidates       []ParityCandidate `json:"candidates"`
}

const (
	resultsSchema = "helm-savings-task-results.v1"
	paritySchema  = "helm-savings-parity-prerun.v1"
)

func main() {
	var (
		proxy        string
		tasksPath    string
		phase        string
		envelopes    string
		requestModel string
		tenant       string
		runID        string
		captureDir   string
		agentID      string
		principalID  string
		workspaceID  string
		maxTokens    int
		timeout      time.Duration
		writeParity  bool
		baselineEnv  string
		rerun        bool
	)
	flag.StringVar(&proxy, "proxy", "http://127.0.0.1:9095", "spend-proxy base URL")
	flag.StringVar(&tasksPath, "tasks", "tasks.json", "task set file")
	flag.StringVar(&phase, "phase", "", "parity (selection subset) or holdout (holdout subset)")
	flag.StringVar(&envelopes, "envelopes", "", "comma-separated spend envelopes to run each task through")
	flag.StringVar(&requestModel, "request-model", "", "model id sent in every request body (the baseline model; substitute envelopes rewrite it server-side, truthfully receipted)")
	flag.StringVar(&tenant, "tenant", "mindburn-dogfood", "tenant id (for spend-intent derivation)")
	flag.StringVar(&runID, "run-id", "", "capture run id (bound into idempotency keys)")
	flag.StringVar(&captureDir, "capture", "", "capture artifacts directory (task_results.json is merged here)")
	flag.StringVar(&agentID, "agent", "agent-paired-replay", "X-HELM-Agent header")
	flag.StringVar(&principalID, "principal", "principal-dogfood", "X-HELM-Principal header")
	flag.StringVar(&workspaceID, "workspace", "ws-dogfood", "X-HELM-Workspace header")
	flag.IntVar(&maxTokens, "max-tokens", 2048, "max_tokens per request (generous: reasoning models bill thinking tokens as output)")
	flag.DurationVar(&timeout, "timeout", 3*time.Minute, "per-request timeout")
	flag.BoolVar(&writeParity, "write-parity", false, "after a parity run, aggregate parity_prerun.json into the capture dir")
	flag.StringVar(&baselineEnv, "baseline-env", "env-baseline", "which envelope is the baseline row in parity_prerun.json")
	flag.BoolVar(&rerun, "rerun", false, "re-execute tasks that already have a recorded result (same idempotency keys; the proxy replays settled calls without double-debit)")
	flag.Parse()

	if phase != "parity" && phase != "holdout" {
		fatal("--phase must be parity or holdout")
	}
	if envelopes == "" || requestModel == "" || runID == "" || captureDir == "" {
		fatal("--envelopes, --request-model, --run-id, and --capture are required")
	}
	subset := "selection"
	if phase == "holdout" {
		subset = "holdout"
	}

	raw, err := os.ReadFile(tasksPath)
	if err != nil {
		fatal("read tasks: %v", err)
	}
	var set TaskSet
	if err := json.Unmarshal(raw, &set); err != nil {
		fatal("parse tasks: %v", err)
	}
	var tasks []Task
	for _, t := range set.Tasks {
		if t.Subset == subset {
			tasks = append(tasks, t)
		}
	}
	if len(tasks) == 0 {
		fatal("no tasks in subset %q", subset)
	}

	if err := os.MkdirAll(captureDir, 0o750); err != nil {
		fatal("create capture dir: %v", err)
	}
	resultsPath := filepath.Join(captureDir, "task_results.json")
	results := loadResults(resultsPath, runID)

	existing := make(map[string]bool, len(results.Results))
	for _, r := range results.Results {
		existing[r.Phase+"\x00"+r.EnvelopeID+"\x00"+r.TaskID] = true
	}

	client := &http.Client{Timeout: timeout}
	envList := splitList(envelopes)
	responseModels := map[string]string{}
	ran, passed := 0, 0
	for _, env := range envList {
		for _, task := range tasks {
			key := phase + "\x00" + env + "\x00" + task.TaskID
			if existing[key] && !rerun {
				fmt.Printf("skip %-8s %-22s %s (already recorded)\n", phase, env, task.TaskID)
				continue
			}
			res, respModel := runTask(client, proxy, tenant, runID, phase, env, requestModel, agentID, principalID, workspaceID, maxTokens, task)
			if respModel != "" {
				responseModels[env] = respModel
			}
			results.Results = upsert(results.Results, res)
			existing[key] = true
			saveResults(resultsPath, results)
			status := "FAIL"
			if res.Passed {
				status = "pass"
				passed++
			}
			ran++
			fmt.Printf("%s %-8s %-22s %-8s intent=%s %s\n", status, phase, env, task.TaskID, res.SpendIntentID, res.FailureReason)
		}
	}
	fmt.Printf("\n%s run complete: %d executed, %d passed (results: %s)\n", phase, ran, passed, resultsPath)

	if writeParity {
		if phase != "parity" {
			fatal("--write-parity is only valid with --phase parity")
		}
		writeParityFile(filepath.Join(captureDir, "parity_prerun.json"), results, tasks, envList, baselineEnv, responseModels, runID)
	}
}

// runTask performs one governed call and evaluates the pass criteria.
func runTask(client *http.Client, proxy, tenant, runID, phase, envelope, requestModel, agentID, principalID, workspaceID string, maxTokens int, task Task) (Result, string) {
	idemKey := fmt.Sprintf("%s-%s-%s-%s", runID, phase, envelope, task.TaskID)
	res := Result{
		TaskID:           task.TaskID,
		Phase:            phase,
		EnvelopeID:       envelope,
		RequestedModelID: requestModel,
		IdempotencyKey:   idemKey,
		SpendIntentID:    spendIntentID(tenant, idemKey),
	}

	body, err := json.Marshal(map[string]any{
		"model":      requestModel,
		"messages":   []map[string]string{{"role": "user", "content": task.Prompt}},
		"max_tokens": maxTokens,
	})
	if err != nil {
		res.FailureReason = "marshal request: " + err.Error()
		res.CompletedAt = time.Now().UTC()
		return res, ""
	}
	req, err := http.NewRequest(http.MethodPost, strings.TrimSuffix(proxy, "/")+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		res.FailureReason = "build request: " + err.Error()
		res.CompletedAt = time.Now().UTC()
		return res, ""
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-HELM-Agent", agentID)
	req.Header.Set("X-HELM-Spend-Envelope", envelope)
	req.Header.Set("X-HELM-Principal", principalID)
	req.Header.Set("X-HELM-Workspace", workspaceID)
	req.Header.Set("X-HELM-Idempotency-Key", idemKey)

	resp, err := client.Do(req)
	if err != nil {
		res.FailureReason = "request failed: " + err.Error()
		res.CompletedAt = time.Now().UTC()
		return res, ""
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	res.HTTPStatus = resp.StatusCode
	res.CompletedAt = time.Now().UTC()
	if err != nil {
		res.FailureReason = "read response: " + err.Error()
		return res, ""
	}

	var parsed struct {
		Model   string `json:"model"`
		Choices []struct {
			FinishReason string `json:"finish_reason"`
			Message      struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil || len(parsed.Choices) == 0 {
		res.FailureReason = fmt.Sprintf("no completion (status %d)", resp.StatusCode)
		return res, ""
	}
	content := parsed.Choices[0].Message.Content
	res.FinishReason = parsed.Choices[0].FinishReason
	sum := sha256.Sum256([]byte(content))
	res.ResponseSHA256 = "sha256:" + hex.EncodeToString(sum[:])

	switch {
	case resp.StatusCode != http.StatusOK:
		res.FailureReason = fmt.Sprintf("http %d", resp.StatusCode)
	case res.FinishReason != "stop":
		res.FailureReason = "finish_reason " + res.FinishReason
	case strings.TrimSpace(content) == "":
		res.FailureReason = "empty answer"
	default:
		ok, why := evaluate(task.Check, content)
		res.Passed = ok
		if !ok {
			res.FailureReason = why
		}
	}
	return res, parsed.Model
}

// evaluate applies the task's deterministic content check.
func evaluate(check Check, content string) (bool, string) {
	switch check.Kind {
	case "contains":
		if strings.Contains(strings.ToLower(content), strings.ToLower(check.Value)) {
			return true, ""
		}
		return false, "answer does not contain " + check.Value
	case "number":
		// Strip thousands separators, then require the number with non-numeric
		// boundaries so 51 does not match 515.
		normalized := strings.ReplaceAll(content, ",", "")
		pattern := `(?:^|[^0-9.])` + regexp.QuoteMeta(check.Value) + `(?:[^0-9.]|$)`
		matched, err := regexp.MatchString(pattern, normalized)
		if err != nil {
			return false, "bad number check: " + err.Error()
		}
		if matched {
			return true, ""
		}
		return false, "expected number " + check.Value
	case "regex":
		matched, err := regexp.MatchString(check.Value, content)
		if err != nil {
			return false, "bad regex: " + err.Error()
		}
		if matched {
			return true, ""
		}
		return false, "regex did not match"
	default:
		return false, "unknown check kind " + check.Kind
	}
}

// spendIntentID mirrors core/pkg/inferencegateway/ids.go so results bind to
// receipts deterministically.
func spendIntentID(tenantID, idempotencyKey string) string {
	sum := sha256.Sum256([]byte(tenantID + "\x00" + idempotencyKey))
	return "si-" + hex.EncodeToString(sum[:])[:24]
}

func loadResults(path, runID string) *ResultsFile {
	results := &ResultsFile{SchemaVersion: resultsSchema, RunID: runID}
	raw, err := os.ReadFile(path)
	if err != nil {
		return results
	}
	if err := json.Unmarshal(raw, results); err != nil {
		fatal("existing results file %s is corrupt: %v", path, err)
	}
	if results.RunID != runID {
		fatal("existing results file %s belongs to run %q, not %q", path, results.RunID, runID)
	}
	return results
}

func upsert(list []Result, res Result) []Result {
	for i, r := range list {
		if r.TaskID == res.TaskID && r.Phase == res.Phase && r.EnvelopeID == res.EnvelopeID {
			list[i] = res
			return list
		}
	}
	list = append(list, res)
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].Phase != list[j].Phase {
			return list[i].Phase < list[j].Phase
		}
		if list[i].EnvelopeID != list[j].EnvelopeID {
			return list[i].EnvelopeID < list[j].EnvelopeID
		}
		return list[i].TaskID < list[j].TaskID
	})
	return list
}

func saveResults(path string, results *ResultsFile) {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fatal("marshal results: %v", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		fatal("write results: %v", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		fatal("replace results: %v", err)
	}
}

// writeParityFile aggregates the parity-phase results into parity_prerun.json.
func writeParityFile(path string, results *ResultsFile, tasks []Task, envList []string, baselineEnv string, responseModels map[string]string, runID string) {
	agg := map[string]*ParityCandidate{}
	for _, env := range envList {
		agg[env] = &ParityCandidate{EnvelopeID: env, DispatchedModelID: responseModels[env]}
	}
	for _, r := range results.Results {
		if r.Phase != "parity" {
			continue
		}
		a := agg[r.EnvelopeID]
		if a == nil {
			continue
		}
		a.TasksRun++
		if r.Passed {
			a.TasksPassed++
		}
	}
	base := agg[baselineEnv]
	if base == nil {
		fatal("baseline envelope %q was not part of this parity run", baselineEnv)
	}
	file := ParityFile{SchemaVersion: paritySchema, RunID: runID, Baseline: *base}
	for _, t := range tasks {
		file.SelectionTaskIDs = append(file.SelectionTaskIDs, t.TaskID)
	}
	sort.Strings(file.SelectionTaskIDs)
	for _, env := range envList {
		if env == baselineEnv {
			continue
		}
		file.Candidates = append(file.Candidates, *agg[env])
	}
	data, err := json.MarshalIndent(&file, "", "  ")
	if err != nil {
		fatal("marshal parity: %v", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		fatal("write parity: %v", err)
	}
	fmt.Printf("parity aggregation written: %s\n", path)
	for _, c := range append([]ParityCandidate{*base}, file.Candidates...) {
		fmt.Printf("  %-22s %-24s %d/%d passed\n", c.EnvelopeID, c.DispatchedModelID, c.TasksPassed, c.TasksRun)
	}
}

func splitList(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "paired-replay: "+format+"\n", args...)
	os.Exit(1)
}
