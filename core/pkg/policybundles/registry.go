// Multi-language policy front-end registry.
//
// HELM compiles policy sources written in CEL, OPA/Rego, and Cedar through
// language-specific compilers, then evaluates them against the same internal
// DecisionRequest. The kernel never branches on language at decision time —
// only the registry does, and only at compile/load.
//
// Workstream B / B3 — Phase 2 of the helm-oss 100% SOTA execution plan.
package policybundles

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/policybundles/cedar"
	regopkg "github.com/Mindburn-Labs/helm-oss/core/pkg/policybundles/rego"
)

// Language tags supported by the registry. Bundle manifests carry one of
// these in a `language` field (default: "cel" for backward compatibility).
const (
	LanguageCEL   = "cel"
	LanguageRego  = "rego"
	LanguageCedar = "cedar"
)

// SupportedLanguages returns the set of policy languages the registry can
// compile + evaluate, in stable order.
func SupportedLanguages() []string {
	return []string{LanguageCEL, LanguageRego, LanguageCedar}
}

// LanguageFromExtension maps a file extension to the canonical language tag.
// Returns the empty string when the extension is not recognized.
func LanguageFromExtension(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".cel":
		return LanguageCEL
	case ".rego":
		return LanguageRego
	case ".cedar":
		return LanguageCedar
	default:
		return ""
	}
}

// IsSupportedLanguage returns true when the tag is a recognized front-end.
func IsSupportedLanguage(lang string) bool {
	switch lang {
	case LanguageCEL, LanguageRego, LanguageCedar:
		return true
	default:
		return false
	}
}

// CompileOptions is the shared compile shape across front-ends. The
// per-language compilers receive the subset of fields they understand.
type CompileOptions struct {
	BundleID    string
	Name        string
	Version     int
	EntitiesDoc string // cedar only
}

// CompileResult is a thin envelope returned by the registry. Callers that
// want the strongly-typed compiled bundle re-cast via the language tag.
type CompileResult struct {
	Language string
	Hash     string
	Rego     *regopkg.CompiledBundle
	Cedar    *cedar.CompiledBundle
}

// Compile dispatches to the per-language compiler.
//
// The CEL path is intentionally a thin pass-through: helm-oss already had
// CEL support before the multi-language work and routes CEL bundles through
// the existing builtin pipeline (see core/pkg/policybundles/builtin.go and
// core/pkg/celcheck/). Callers that pass language=cel today receive a
// "not handled by registry" sentinel and should call the existing CEL
// path directly until that path is migrated under this registry in a
// follow-up PR.
func Compile(ctx context.Context, language, source string, opts CompileOptions) (*CompileResult, error) {
	if !IsSupportedLanguage(language) {
		return nil, fmt.Errorf("policybundles: unsupported language %q (supported: %v)", language, SupportedLanguages())
	}
	switch language {
	case LanguageRego:
		b, err := regopkg.Compile(source, regopkg.CompileOptions{
			BundleID: opts.BundleID,
			Name:     opts.Name,
			Version:  opts.Version,
		})
		if err != nil {
			return nil, err
		}
		return &CompileResult{Language: language, Hash: b.Hash, Rego: b}, nil
	case LanguageCedar:
		b, err := cedar.Compile(source, cedar.CompileOptions{
			BundleID:    opts.BundleID,
			Name:        opts.Name,
			Version:     opts.Version,
			EntitiesDoc: opts.EntitiesDoc,
		})
		if err != nil {
			return nil, err
		}
		return &CompileResult{Language: language, Hash: b.Hash, Cedar: b}, nil
	case LanguageCEL:
		// CEL routes through the existing builtin / celcheck pipeline.
		// The registry advertises CEL as supported but does not yet own
		// its compile path; callers should keep using the existing entry
		// point until a follow-up migration unifies them.
		return nil, fmt.Errorf("policybundles: language=cel is not yet routed through the registry; use the existing celcheck path")
	}
	return nil, fmt.Errorf("policybundles: unreachable language dispatch")
}

// DetectLanguage chooses a language tag for the given source path. When
// `explicit` is non-empty it wins; otherwise the file extension decides;
// otherwise the function returns an error so callers do not silently
// fall through to the wrong evaluator.
func DetectLanguage(explicit, path string) (string, error) {
	if explicit != "" {
		if !IsSupportedLanguage(explicit) {
			return "", fmt.Errorf("policybundles: unsupported language %q", explicit)
		}
		return explicit, nil
	}
	if ext := LanguageFromExtension(path); ext != "" {
		return ext, nil
	}
	return "", fmt.Errorf("policybundles: could not detect language for %q (use --language=<cel|rego|cedar>)", path)
}
