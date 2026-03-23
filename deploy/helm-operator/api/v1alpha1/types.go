// Package v1alpha1 defines the HELM Kubernetes Operator Custom Resource Definitions.
//
// Two CRDs are defined:
//   - PolicyBundle: Declares a signed policy bundle to be loaded into Guardian
//   - GuardianSidecar: Annotation-driven sidecar injection for governed workloads
package v1alpha1

import (
	"time"
)

// ── PolicyBundle CRD ─────────────────────────────────────────

// PolicyBundle declares a signed policy bundle to be reconciled and loaded
// into the Guardian runtime. The controller watches for PolicyBundle CRs
// and ensures the Guardian instance has the correct policy bundle loaded.
//
// apiVersion: helm.mindburn.org/v1alpha1
// kind: PolicyBundle
type PolicyBundle struct {
	TypeMeta   `json:",inline"`
	ObjectMeta `json:"metadata,omitempty"`
	Spec       PolicyBundleSpec   `json:"spec"`
	Status     PolicyBundleStatus `json:"status,omitempty"`
}

// PolicyBundleSpec defines the desired state of a PolicyBundle.
type PolicyBundleSpec struct {
	// BundleID is the unique identifier for this policy bundle.
	BundleID string `json:"bundleId"`
	// Version is the semantic version of the bundle (monotonically increasing).
	Version int `json:"version"`
	// ContentHash is the SHA-256 content-addressed hash of the bundle rules.
	ContentHash string `json:"contentHash"`
	// Signature is the HSM-backed signature of the content hash.
	Signature string `json:"signature"`
	// SignerKeyID identifies the key used to sign the bundle.
	SignerKeyID string `json:"signerKeyId"`
	// SourceURL is the URL from which to fetch the bundle archive.
	SourceURL string `json:"sourceUrl,omitempty"`
	// ConformanceLevel is the minimum conformance level required (L1, L2, L3).
	ConformanceLevel string `json:"conformanceLevel"`
	// RefreshInterval is how often to check for bundle updates.
	RefreshInterval string `json:"refreshInterval,omitempty"`
}

// PolicyBundleStatus defines the observed state of a PolicyBundle.
type PolicyBundleStatus struct {
	// Phase is the current lifecycle phase (Pending, Active, Failed, Superseded).
	Phase string `json:"phase"`
	// LoadedAt is when the bundle was last successfully loaded.
	LoadedAt *time.Time `json:"loadedAt,omitempty"`
	// VerifiedHash is the hash verified during loading.
	VerifiedHash string `json:"verifiedHash,omitempty"`
	// ErrorMessage contains details if Phase is Failed.
	ErrorMessage string `json:"errorMessage,omitempty"`
	// ObservedGeneration tracks which spec version the status reflects.
	ObservedGeneration int64 `json:"observedGeneration"`
}

// ── GuardianSidecar CRD ──────────────────────────────────────

// GuardianSidecar specifies how to inject and configure a Guardian
// sidecar container into governed workloads.
//
// apiVersion: helm.mindburn.org/v1alpha1
// kind: GuardianSidecar
type GuardianSidecar struct {
	TypeMeta   `json:",inline"`
	ObjectMeta `json:"metadata,omitempty"`
	Spec       GuardianSidecarSpec   `json:"spec"`
	Status     GuardianSidecarStatus `json:"status,omitempty"`
}

// GuardianSidecarSpec defines the desired sidecar injection configuration.
type GuardianSidecarSpec struct {
	// Image is the Guardian container image.
	Image string `json:"image"`
	// ConformanceLevel is the minimum level to enforce (L1, L2, L3).
	ConformanceLevel string `json:"conformanceLevel"`
	// PolicyBundleRef references the PolicyBundle CR to use.
	PolicyBundleRef string `json:"policyBundleRef"`
	// NamespaceSelector determines which namespaces to inject into.
	NamespaceSelector *LabelSelector `json:"namespaceSelector,omitempty"`
	// PodSelector determines which pods to inject into.
	PodSelector *LabelSelector `json:"podSelector,omitempty"`
	// Resources defines container resource requests/limits.
	Resources *ResourceRequirements `json:"resources,omitempty"`
	// FailClosed controls whether the sidecar blocks if it fails to start.
	FailClosed bool `json:"failClosed"`
}

// GuardianSidecarStatus defines the observed sidecar state.
type GuardianSidecarStatus struct {
	// InjectedPodCount is the number of pods with active sidecars.
	InjectedPodCount int `json:"injectedPodCount"`
	// Phase is the injection phase (Ready, Injecting, Error).
	Phase string `json:"phase"`
	// ObservedGeneration tracks spec version coverage.
	ObservedGeneration int64 `json:"observedGeneration"`
}

// ── Shared K8s Types (minimal, no dependency on k8s.io/api) ─

// TypeMeta describes the API version and kind of an object.
type TypeMeta struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
}

// ObjectMeta holds standard object metadata.
type ObjectMeta struct {
	Name              string            `json:"name"`
	Namespace         string            `json:"namespace,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
	Annotations       map[string]string `json:"annotations,omitempty"`
	Generation        int64             `json:"generation,omitempty"`
	ResourceVersion   string            `json:"resourceVersion,omitempty"`
}

// LabelSelector selects objects by labels.
type LabelSelector struct {
	MatchLabels map[string]string `json:"matchLabels,omitempty"`
}

// ResourceRequirements specifies compute resource requests and limits.
type ResourceRequirements struct {
	Requests ResourceList `json:"requests,omitempty"`
	Limits   ResourceList `json:"limits,omitempty"`
}

// ResourceList is a map of resource name to quantity string.
type ResourceList map[string]string

// ── GroupVersion Registration ────────────────────────────────

const (
	// GroupName is the API group for HELM CRDs.
	GroupName = "helm.mindburn.org"
	// GroupVersion is the API version.
	GroupVersion = "v1alpha1"
	// APIVersion is the fully-qualified API version string.
	APIVersion = GroupName + "/" + GroupVersion
)
