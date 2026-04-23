// Package context — Context namespaces.
//
// Per HELM 2030 Spec §5.4:
//
//	The context fabric provides typed namespaces for structuring
//	governance-relevant information. Each namespace defines what
//	context data is available for policy evaluation.
package context

// Namespace is a typed context category for policy evaluation.
type Namespace string

const (
	// Existing namespaces (inferred from assembler usage)
	NSIdentity    Namespace = "identity"
	NSObligation  Namespace = "obligation"
	NSPolicy      Namespace = "policy"
	NSExecution   Namespace = "execution"
	NSEnvironment Namespace = "environment"

	// GAP-15: Vendor namespace
	NSVendor Namespace = "vendor"

	// GAP-16: Asset namespace
	NSAsset Namespace = "asset"

	// GAP-17: Actuator namespace
	NSActuator Namespace = "actuator"

	// GAP-18: Facility namespace
	NSFacility Namespace = "facility"

	// Additional canonical namespaces
	NSEconomic   Namespace = "economic"
	NSTemporal   Namespace = "temporal"
	NSGeospatial Namespace = "geospatial"
)

// NamespaceSchema defines what data a namespace contains.
type NamespaceSchema struct {
	Namespace   Namespace        `json:"namespace"`
	Description string           `json:"description"`
	Fields      []NamespaceField `json:"fields"`
	Required    bool             `json:"required"` // must be populated for policy eval
}

// NamespaceField is a single field in a namespace schema.
type NamespaceField struct {
	Name        string `json:"name"`
	Type        string `json:"type"` // "string", "int64", "float64", "bool", "time", "object"
	Required    bool   `json:"required"`
	Description string `json:"description"`
}

// ContextSlice is a filtered view of context for a specific evaluation.
// GAP-22: Formal context slicing contracts.
type ContextSlice struct {
	Namespaces []Namespace                          `json:"namespaces"`
	Data       map[Namespace]map[string]interface{} `json:"data"`
	SliceID    string                               `json:"slice_id"`
	CreatedFor string                               `json:"created_for"` // policy or decision ID
}

// NewContextSlice creates a context slice for a subset of namespaces.
func NewContextSlice(sliceID, createdFor string, namespaces []Namespace) *ContextSlice {
	return &ContextSlice{
		Namespaces: namespaces,
		Data:       make(map[Namespace]map[string]interface{}),
		SliceID:    sliceID,
		CreatedFor: createdFor,
	}
}

// Set adds data to a namespace within the slice.
func (cs *ContextSlice) Set(ns Namespace, key string, value interface{}) {
	if cs.Data[ns] == nil {
		cs.Data[ns] = make(map[string]interface{})
	}
	cs.Data[ns][key] = value
}

// Get retrieves data from a namespace within the slice.
func (cs *ContextSlice) Get(ns Namespace, key string) (interface{}, bool) {
	if cs.Data[ns] == nil {
		return nil, false
	}
	v, ok := cs.Data[ns][key]
	return v, ok
}

// HasNamespace checks if the slice includes a given namespace.
func (cs *ContextSlice) HasNamespace(ns Namespace) bool {
	for _, n := range cs.Namespaces {
		if n == ns {
			return true
		}
	}
	return false
}

// CanonicalNamespaces returns schemas for all canonical namespaces.
func CanonicalNamespaces() []NamespaceSchema {
	return []NamespaceSchema{
		{Namespace: NSIdentity, Description: "Actor identity context", Required: true},
		{Namespace: NSObligation, Description: "Active obligations and tasks", Required: true},
		{Namespace: NSPolicy, Description: "Applicable policies and rules"},
		{Namespace: NSExecution, Description: "Runtime execution context"},
		{Namespace: NSEnvironment, Description: "Runtime environment metadata"},
		{Namespace: NSVendor, Description: "Vendor relationships and contracts"},
		{Namespace: NSAsset, Description: "Managed assets and resources"},
		{Namespace: NSActuator, Description: "Available actuators and their state"},
		{Namespace: NSFacility, Description: "Physical facility context"},
		{Namespace: NSEconomic, Description: "Budget, spend, and treasury context"},
		{Namespace: NSTemporal, Description: "Time-based context (deadlines, schedules)"},
		{Namespace: NSGeospatial, Description: "Location and jurisdiction context"},
	}
}
