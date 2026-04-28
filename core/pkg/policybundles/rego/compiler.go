package rego

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

//go:embed capabilities.json
var capabilitiesJSON []byte

// capabilitiesPolicy is the parsed form of capabilities.json. Only the
// denied_builtins list is enforced; the rest of the file is documentation.
type capabilitiesPolicy struct {
	DeniedBuiltins []string `json:"denied_builtins"`
}

// rootCtx returns the context used for compilation and evaluation.
// Decoupled so tests can override.
func rootCtx() context.Context { return context.Background() }

// loadCapabilities returns an OPA *ast.Capabilities with all denied
// builtins removed from the default set, plus an empty allow_net list
// so http.send and net.* lookups have no permitted destinations.
func loadCapabilities() (*ast.Capabilities, []byte, error) {
	var pol capabilitiesPolicy
	if err := json.Unmarshal(capabilitiesJSON, &pol); err != nil {
		return nil, nil, fmt.Errorf("rego: parse capabilities.json: %w", err)
	}

	caps := ast.CapabilitiesForThisVersion()
	denied := make(map[string]struct{}, len(pol.DeniedBuiltins))
	for _, name := range pol.DeniedBuiltins {
		denied[name] = struct{}{}
	}

	filtered := caps.Builtins[:0]
	for _, b := range caps.Builtins {
		if _, drop := denied[b.Name]; drop {
			continue
		}
		filtered = append(filtered, b)
	}
	caps.Builtins = filtered

	// Forbid all network access — no http.send destination is allowed.
	caps.AllowNet = []string{}

	return caps, capabilitiesJSON, nil
}

// CompileOptions controls how a Rego module is compiled into a HELM
// policy bundle. Defaults: query "data.helm.policy.decision" and module
// path "policy.rego".
type CompileOptions struct {
	BundleID   string
	Name       string
	Version    int
	Query      string
	ModulePath string
	Now        func() time.Time
}

// Compile parses, type-checks, and validates a Rego module against the
// HELM-restricted capabilities, then returns a CompiledBundle whose Hash
// can be signed and stored alongside CEL and Cedar bundles. The module
// is not pre-evaluated; Evaluate() recompiles from the persisted source
// for replayability.
func Compile(module string, opts CompileOptions) (*CompiledBundle, error) {
	if strings.TrimSpace(module) == "" {
		return nil, fmt.Errorf("rego: empty module")
	}
	if opts.Query == "" {
		opts.Query = "data.helm.policy.decision"
	}
	if opts.ModulePath == "" {
		opts.ModulePath = "policy.rego"
	}
	if opts.Version == 0 {
		opts.Version = 1
	}
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}

	caps, capsBytes, err := loadCapabilities()
	if err != nil {
		return nil, err
	}

	// PrepareForEval forces parsing, type-checking, and capability validation
	// in one pass. Any disallowed builtin (http.send, time.now_ns, rand.intn,
	// crypto.x509.parse_certificates, ...) surfaces here as a compile error.
	_, err = rego.New(
		rego.Query(opts.Query),
		rego.Module(opts.ModulePath, module),
		rego.Capabilities(caps),
		rego.StrictBuiltinErrors(true),
	).PrepareForEval(rootCtx())
	if err != nil {
		return nil, fmt.Errorf("rego: compile failed: %w", err)
	}

	bundle := &CompiledBundle{
		BundleID:     opts.BundleID,
		Name:         opts.Name,
		Version:      opts.Version,
		Language:     Language,
		Module:       module,
		Query:        opts.Query,
		Capabilities: capsBytes,
		CompiledAt:   opts.Now().UTC(),
	}

	hash, err := computeHash(bundle)
	if err != nil {
		return nil, err
	}
	bundle.Hash = hash
	return bundle, nil
}
