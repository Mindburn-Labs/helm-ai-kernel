package cedar

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	cedar "github.com/cedar-policy/cedar-go"
)

// CompileOptions controls how a Cedar policy set is compiled into a HELM
// policy bundle.
type CompileOptions struct {
	BundleID string
	Name     string
	Version  int
	// EntitiesDoc is an optional Cedar entities JSON document baked into
	// the bundle. When non-empty it is parsed at compile time to surface
	// any entity-shape errors before signing.
	EntitiesDoc string
	Now         func() time.Time
}

// Compile parses and validates a Cedar policy set, optionally checks an
// entities JSON document, and returns a CompiledBundle whose Hash can be
// signed and stored alongside CEL and Rego bundles.
func Compile(policySet string, opts CompileOptions) (*CompiledBundle, error) {
	if strings.TrimSpace(policySet) == "" {
		return nil, fmt.Errorf("cedar: empty policy set")
	}
	if opts.Version == 0 {
		opts.Version = 1
	}
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}

	if _, err := parsePolicySet(opts.Name, policySet); err != nil {
		return nil, err
	}

	if strings.TrimSpace(opts.EntitiesDoc) != "" {
		var entities cedar.EntityMap
		if err := json.Unmarshal([]byte(opts.EntitiesDoc), &entities); err != nil {
			return nil, fmt.Errorf("cedar: parse entities: %w", err)
		}
	}

	bundle := &CompiledBundle{
		BundleID:    opts.BundleID,
		Name:        opts.Name,
		Version:     opts.Version,
		Language:    Language,
		PolicySet:   policySet,
		EntitiesDoc: opts.EntitiesDoc,
		CompiledAt:  opts.Now().UTC(),
	}

	hash, err := computeHash(bundle)
	if err != nil {
		return nil, err
	}
	bundle.Hash = hash
	return bundle, nil
}

// parsePolicySet returns a fully-parsed cedar.PolicySet or a typed error.
// fileName is propagated into Cedar's error positions for diagnostics.
func parsePolicySet(fileName, src string) (*cedar.PolicySet, error) {
	name := fileName
	if name == "" {
		name = "policy.cedar"
	}
	ps, err := cedar.NewPolicySetFromBytes(name, []byte(src))
	if err != nil {
		return nil, fmt.Errorf("cedar: parse policy set: %w", err)
	}
	return ps, nil
}
