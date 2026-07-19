package contracts

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

const (
	LaunchConstraintSetSchemaVersion      = "launch_constraint_set.v1"
	LaunchRouteQuoteSchemaVersion         = "launch_route_quote.v1"
	LaunchResourceGraphSchemaVersion      = "launch_resource_graph.v1"
	LaunchProviderPayloadSetSchemaVersion = "launch_provider_payload_set.v1"
	LaunchBlueprintSchemaVersion          = "launch_blueprint.v1"
	LaunchPortableVocabularyVersion       = "launch_portable_vocabulary.v1"
	LaunchCreditVerified                  = "ACTIVE_CREDIT_VERIFIED"
	LaunchCreditAdvisory                  = "MAY_QUALIFY"
	LaunchCreditNone                      = "NONE"
	LaunchCreditUnknown                   = "UNKNOWN"
)

var launchCurrencyPattern = regexp.MustCompile(`^[A-Z]{3}$`)

var launchBlueprintIDPattern = regexp.MustCompile(`^blueprint:sha256:[a-f0-9]{64}$`)

var launchBlueprintNodeIDPattern = regexp.MustCompile(`^node-[0-9]{4}$`)

// Clean-room blueprints deliberately use a small, versioned public vocabulary.
// Repository analysis and certified provider profiles remain extensible, but an
// unregistered vendor or tenant token must never be copied into a shareable
// blueprint. New portable semantics require an explicit contract release.
var launchPortableWorkloadKinds = map[string]struct{}{
	"cache": {}, "composite": {}, "container": {}, "database": {},
	"function": {}, "gpu_workload": {}, "http_service": {}, "infrastructure": {},
	"kubernetes_workload": {}, "message_queue": {}, "object_storage": {},
	"scheduled_job": {}, "static_site": {}, "worker": {},
}

var launchPortableCapabilities = map[string]struct{}{
	"autoscaling": {}, "custom-domain": {}, "gpu-runtime": {}, "health-check": {},
	"http-ingress": {}, "https-endpoint": {}, "managed-mysql": {},
	"managed-postgresql": {}, "managed-redis": {}, "object-storage": {},
	"persistent-storage": {}, "private-network": {}, "scheduled-execution": {},
	"secret-injection": {}, "stateless-runtime": {}, "websocket": {},
	"zero-downtime-release": {},
}

var launchPortableRelationships = map[string]struct{}{
	"connects_to": {}, "depends_on": {}, "mounts": {}, "publishes_to": {},
	"reads_from": {}, "replicates_to": {}, "routes_to": {}, "scheduled_by": {},
	"subscribes_to": {}, "writes_to": {},
}

var launchPortableResidencyTags = map[string]struct{}{
	"customer-selected": {}, "eea": {}, "eu": {}, "global": {}, "uk": {}, "us": {},
}

var launchPortableCommitmentTerms = map[string]struct{}{
	"annual": {}, "hourly": {}, "monthly": {}, "prepaid": {}, "spot": {},
}

// LaunchConstraintSet is the versioned, approval-bound policy input to route
// selection. The Kernel stays provider-neutral: individual missions can bind
// EU-only, a EUR 50 cap, monthly commitment, or a different policy without
// compiling those commercial choices into the effect taxonomy.
type LaunchConstraintSet struct {
	SchemaVersion             string   `json:"schema_version"`
	ConstraintSetID           string   `json:"constraint_set_id"`
	TenantID                  string   `json:"tenant_id"`
	WorkspaceID               string   `json:"workspace_id"`
	MissionID                 string   `json:"mission_id"`
	MaximumGrossCurrency      string   `json:"maximum_gross_currency"`
	MaximumGrossMinor         int64    `json:"maximum_gross_minor"`
	AllowedProviders          []string `json:"allowed_providers"`
	AllowedJurisdictions      []string `json:"allowed_jurisdictions"`
	RequiredResidencyTags     []string `json:"required_residency_tags"`
	AllowedCommitmentTerms    []string `json:"allowed_commitment_terms"`
	RequiredRouteCapabilities []string `json:"required_route_capabilities"`
	PolicyExpressionHash      string   `json:"policy_expression_hash"`
}

type LaunchRouteQuote struct {
	SchemaVersion          string                `json:"schema_version"`
	QuoteID                string                `json:"quote_id"`
	TenantID               string                `json:"tenant_id"`
	WorkspaceID            string                `json:"workspace_id"`
	MissionID              string                `json:"mission_id"`
	WorkloadGraphHash      string                `json:"workload_graph_hash"`
	ConstraintSetHash      string                `json:"constraint_set_hash"`
	Currency               string                `json:"currency"`
	PlacementCosts         []LaunchPlacementCost `json:"placement_costs"`
	BaseProviderCostMinor  int64                 `json:"base_provider_cost_minor"`
	TaxFXReserveMinor      int64                 `json:"tax_fx_reserve_minor"`
	GrossExposureMinor     int64                 `json:"gross_exposure_minor"`
	VerifiedCreditMinor    int64                 `json:"verified_credit_minor"`
	ExpectedCashMinor      int64                 `json:"expected_cash_minor"`
	CreditStatus           string                `json:"credit_status"`
	CreditSnapshotHash     string                `json:"credit_snapshot_hash"`
	FXSnapshotHash         string                `json:"fx_snapshot_hash"`
	TaxSnapshotHash        string                `json:"tax_snapshot_hash"`
	CommercialEvidenceHash string                `json:"commercial_evidence_hash"`
	RetrievedAt            string                `json:"retrieved_at"`
	ExpiresAt              string                `json:"expires_at"`
}

type LaunchPlacementCost struct {
	PlacementID         string `json:"placement_id"`
	ProviderID          string `json:"provider_id"`
	ProviderAccountHash string `json:"provider_account_hash"`
	RegionID            string `json:"region_id"`
	OfferingID          string `json:"offering_id"`
	BillingCadence      string `json:"billing_cadence"`
	CommitmentTerm      string `json:"commitment_term"`
	BaseCostMinor       int64  `json:"base_cost_minor"`
	TaxFXReserveMinor   int64  `json:"tax_fx_reserve_minor"`
	GrossExposureMinor  int64  `json:"gross_exposure_minor"`
	VerifiedCreditMinor int64  `json:"verified_credit_minor"`
	ExpectedCashMinor   int64  `json:"expected_cash_minor"`
	CreditStatus        string `json:"credit_status"`
	OfferSnapshotRef    string `json:"offer_snapshot_ref"`
	OfferSnapshotHash   string `json:"offer_snapshot_hash"`
	PriceEvidenceHash   string `json:"price_evidence_hash"`
	TermsEvidenceHash   string `json:"terms_evidence_hash"`
}

type LaunchResourceGraph struct {
	SchemaVersion   string               `json:"schema_version"`
	ResourceGraphID string               `json:"resource_graph_id"`
	TenantID        string               `json:"tenant_id"`
	WorkspaceID     string               `json:"workspace_id"`
	MissionID       string               `json:"mission_id"`
	Nodes           []LaunchResourceNode `json:"nodes"`
	Edges           []LaunchResourceEdge `json:"edges"`
}

type LaunchResourceNode struct {
	ResourceID       string `json:"resource_id"`
	PlacementID      string `json:"placement_id"`
	WorkloadNodeID   string `json:"workload_node_id"`
	ResourceKind     string `json:"resource_kind"`
	LifecycleClass   string `json:"lifecycle_class"`
	DesiredStateHash string `json:"desired_state_hash"`
	OwnershipTagHash string `json:"ownership_tag_hash"`
}

type LaunchResourceEdge struct {
	FromResourceID string `json:"from_resource_id"`
	ToResourceID   string `json:"to_resource_id"`
	Relationship   string `json:"relationship"`
}

type LaunchProviderPayloadSet struct {
	SchemaVersion string                       `json:"schema_version"`
	PayloadSetID  string                       `json:"payload_set_id"`
	TenantID      string                       `json:"tenant_id"`
	WorkspaceID   string                       `json:"workspace_id"`
	MissionID     string                       `json:"mission_id"`
	Entries       []LaunchProviderPayloadEntry `json:"entries"`
}

type LaunchProviderPayloadEntry struct {
	PlacementID       string `json:"placement_id"`
	EffectID          string `json:"effect_id"`
	ProviderActionURN string `json:"provider_action_urn"`
	PayloadHash       string `json:"payload_hash"`
}

// LaunchBlueprint is intentionally clean-room: it contains only a workload
// shape and portable constraints. It has no source/account/provider identity,
// approvals, payloads, receipts, or EvidencePack references. Provider-specific
// semantics remain private until an explicit portable-vocabulary mapping ships.
type LaunchBlueprint struct {
	SchemaVersion             string                    `json:"schema_version"`
	PortableVocabularyVersion string                    `json:"portable_vocabulary_version"`
	BlueprintID               string                    `json:"blueprint_id"`
	SourceReconnectRequired   bool                      `json:"source_reconnect_required"`
	ProviderSelectionRequired bool                      `json:"provider_selection_required"`
	Nodes                     []LaunchBlueprintNode     `json:"nodes"`
	Edges                     []LaunchBlueprintEdge     `json:"edges"`
	Constraints               LaunchBlueprintConstraint `json:"constraints"`
}

type LaunchBlueprintNode struct {
	NodeID               string   `json:"node_id"`
	Kind                 string   `json:"kind"`
	LifecycleClass       string   `json:"lifecycle_class"`
	RequiredCapabilities []string `json:"required_capabilities"`
}

type LaunchBlueprintEdge struct {
	FromNodeID   string `json:"from_node_id"`
	ToNodeID     string `json:"to_node_id"`
	Relationship string `json:"relationship"`
}

type LaunchBlueprintConstraint struct {
	MaximumGrossCurrency      string   `json:"maximum_gross_currency"`
	MaximumGrossMinor         int64    `json:"maximum_gross_minor"`
	AllowedJurisdictions      []string `json:"allowed_jurisdictions"`
	RequiredResidencyTags     []string `json:"required_residency_tags"`
	AllowedCommitmentTerms    []string `json:"allowed_commitment_terms"`
	RequiredRouteCapabilities []string `json:"required_route_capabilities"`
}

func DeriveLaunchConstraintSetHash(value LaunchConstraintSet) (string, error) {
	return deriveLaunchCanonicalHash(value, "constraint set")
}

func DeriveLaunchRouteQuoteHash(value LaunchRouteQuote) (string, error) {
	return deriveLaunchCanonicalHash(value, "route quote")
}

func DeriveLaunchOfferSnapshotSetHash(costs []LaunchPlacementCost) (string, error) {
	projection := make([]struct {
		PlacementID       string `json:"placement_id"`
		OfferSnapshotRef  string `json:"offer_snapshot_ref"`
		OfferSnapshotHash string `json:"offer_snapshot_hash"`
	}, len(costs))
	for index, cost := range costs {
		projection[index].PlacementID = cost.PlacementID
		projection[index].OfferSnapshotRef = cost.OfferSnapshotRef
		projection[index].OfferSnapshotHash = cost.OfferSnapshotHash
	}
	return deriveLaunchCanonicalHash(projection, "offer snapshot set")
}

func DeriveLaunchResourceGraphHash(value LaunchResourceGraph) (string, error) {
	return deriveLaunchCanonicalHash(value, "resource graph")
}

func DeriveLaunchProviderPayloadSetHash(value LaunchProviderPayloadSet) (string, error) {
	return deriveLaunchCanonicalHash(value, "provider payload set")
}

func DeriveLaunchBlueprintHash(value LaunchBlueprint) (string, error) {
	return deriveLaunchCanonicalHash(value, "blueprint")
}

// DeriveLaunchBlueprintID returns the clean-room identity bound to sanitized
// blueprint content. The identifier field itself is excluded from the digest.
func DeriveLaunchBlueprintID(value LaunchBlueprint) (string, error) {
	projection := value
	projection.BlueprintID = ""
	hash, err := canonicalize.CanonicalHash(projection)
	if err != nil {
		return "", fmt.Errorf("derive sanitized launch blueprint identity: %w", err)
	}
	return "blueprint:sha256:" + hash, nil
}

func deriveLaunchCanonicalHash(value any, label string) (string, error) {
	hash, err := canonicalize.CanonicalHash(value)
	if err != nil {
		return "", fmt.Errorf("derive launch %s hash: %w", label, err)
	}
	return "sha256:" + hash, nil
}

func ValidateLaunchConstraintSet(value LaunchConstraintSet) error {
	if value.SchemaVersion != LaunchConstraintSetSchemaVersion || value.ConstraintSetID == "" || value.TenantID == "" || value.WorkspaceID == "" || value.MissionID == "" {
		return errors.New("launch constraint set identity is incomplete")
	}
	if !launchCurrencyPattern.MatchString(value.MaximumGrossCurrency) || value.MaximumGrossMinor < 0 || !validLaunchSHA256(value.PolicyExpressionHash) {
		return errors.New("launch constraint set gross cap or policy expression is invalid")
	}
	for name, values := range map[string][]string{
		"allowed providers":           value.AllowedProviders,
		"allowed jurisdictions":       value.AllowedJurisdictions,
		"required residency tags":     value.RequiredResidencyTags,
		"allowed commitment terms":    value.AllowedCommitmentTerms,
		"required route capabilities": value.RequiredRouteCapabilities,
	} {
		if err := validateSortedUniqueOptional(values, name); err != nil {
			return err
		}
	}
	return nil
}

func ValidateLaunchRouteQuote(value LaunchRouteQuote) error {
	if value.SchemaVersion != LaunchRouteQuoteSchemaVersion || value.QuoteID == "" || value.TenantID == "" || value.WorkspaceID == "" || value.MissionID == "" {
		return errors.New("launch route quote identity is incomplete")
	}
	if !validLaunchSHA256(value.WorkloadGraphHash) || !validLaunchSHA256(value.ConstraintSetHash) || !launchCurrencyPattern.MatchString(value.Currency) || len(value.PlacementCosts) == 0 {
		return errors.New("launch route quote graph, constraints, currency, or placements are invalid")
	}
	for field, hash := range map[string]string{
		"credit_snapshot_hash":     value.CreditSnapshotHash,
		"fx_snapshot_hash":         value.FXSnapshotHash,
		"tax_snapshot_hash":        value.TaxSnapshotHash,
		"commercial_evidence_hash": value.CommercialEvidenceHash,
	} {
		if !validLaunchSHA256(hash) {
			return fmt.Errorf("launch route quote %s is invalid", field)
		}
	}
	var baseTotal, reserveTotal, grossTotal, creditTotal, expectedCashTotal int64
	lineStatuses := make([]string, 0, len(value.PlacementCosts))
	creditedAccounts := make(map[string]string)
	creditedSnapshots := make(map[string]string)
	previous := ""
	for _, line := range value.PlacementCosts {
		if line.PlacementID == "" || line.PlacementID <= previous || line.ProviderID == "" || line.RegionID == "" || line.OfferingID == "" || line.BillingCadence == "" || line.CommitmentTerm == "" {
			return errors.New("launch route quote placement costs must be complete, unique, and sorted")
		}
		previous = line.PlacementID
		if !validLaunchSHA256(line.ProviderAccountHash) || line.OfferSnapshotRef == "" || !validLaunchSHA256(line.OfferSnapshotHash) || !validLaunchSHA256(line.PriceEvidenceHash) || !validLaunchSHA256(line.TermsEvidenceHash) || line.BaseCostMinor < 0 || line.TaxFXReserveMinor < 0 || line.GrossExposureMinor < 0 || line.VerifiedCreditMinor < 0 || line.ExpectedCashMinor < 0 {
			return fmt.Errorf("launch route quote placement %s has invalid cost evidence", line.PlacementID)
		}
		lineGross, ok := addLaunchMinor(line.BaseCostMinor, line.TaxFXReserveMinor)
		if !ok || lineGross != line.GrossExposureMinor {
			return fmt.Errorf("launch route quote placement %s gross exposure is inconsistent", line.PlacementID)
		}
		if line.VerifiedCreditMinor > line.BaseCostMinor {
			return fmt.Errorf("launch route quote placement %s verified credit exceeds provider cost", line.PlacementID)
		}
		switch line.CreditStatus {
		case LaunchCreditVerified:
			if line.VerifiedCreditMinor <= 0 {
				return fmt.Errorf("launch route quote placement %s verified status has no active credit", line.PlacementID)
			}
			accountKey := launchTupleKey(line.ProviderID, line.ProviderAccountHash)
			if prior, exists := creditedAccounts[accountKey]; exists {
				return fmt.Errorf("launch route quote placements %s and %s apply verified credit more than once to one provider account", prior, line.PlacementID)
			}
			creditedAccounts[accountKey] = line.PlacementID
			snapshotKey := launchTupleKey(line.OfferSnapshotRef, line.OfferSnapshotHash)
			if prior, exists := creditedSnapshots[snapshotKey]; exists {
				return fmt.Errorf("launch route quote placements %s and %s apply one verified credit snapshot more than once", prior, line.PlacementID)
			}
			creditedSnapshots[snapshotKey] = line.PlacementID
		case LaunchCreditAdvisory, LaunchCreditNone, LaunchCreditUnknown:
			if line.VerifiedCreditMinor != 0 {
				return fmt.Errorf("launch route quote placement %s unverified status reduced expected cash", line.PlacementID)
			}
		default:
			return fmt.Errorf("launch route quote placement %s credit status is invalid", line.PlacementID)
		}
		lineExpectedCash := line.GrossExposureMinor - line.VerifiedCreditMinor
		if lineExpectedCash < 0 {
			lineExpectedCash = 0
		}
		if line.ExpectedCashMinor != lineExpectedCash {
			return fmt.Errorf("launch route quote placement %s expected cash is inconsistent", line.PlacementID)
		}
		lineStatuses = append(lineStatuses, line.CreditStatus)
		var sumOK bool
		baseTotal, sumOK = addLaunchMinor(baseTotal, line.BaseCostMinor)
		if !sumOK {
			return errors.New("launch route quote base cost overflows int64")
		}
		reserveTotal, sumOK = addLaunchMinor(reserveTotal, line.TaxFXReserveMinor)
		if !sumOK {
			return errors.New("launch route quote reserve overflows int64")
		}
		grossTotal, sumOK = addLaunchMinor(grossTotal, line.GrossExposureMinor)
		if !sumOK {
			return errors.New("launch route quote gross exposure overflows int64")
		}
		creditTotal, sumOK = addLaunchMinor(creditTotal, line.VerifiedCreditMinor)
		if !sumOK {
			return errors.New("launch route quote verified credit overflows int64")
		}
		expectedCashTotal, sumOK = addLaunchMinor(expectedCashTotal, line.ExpectedCashMinor)
		if !sumOK {
			return errors.New("launch route quote expected cash overflows int64")
		}
	}
	if value.BaseProviderCostMinor != baseTotal || value.TaxFXReserveMinor != reserveTotal || value.GrossExposureMinor != grossTotal || value.VerifiedCreditMinor != creditTotal || value.ExpectedCashMinor != expectedCashTotal {
		return errors.New("launch route quote totals do not equal placement costs")
	}
	if value.CreditStatus != aggregateLaunchCreditStatus(lineStatuses) {
		return errors.New("launch route quote credit status does not aggregate placement evidence")
	}
	offerSetHash, err := DeriveLaunchOfferSnapshotSetHash(value.PlacementCosts)
	if err != nil || !launchConstantEqual(value.CreditSnapshotHash, offerSetHash) {
		return errors.New("launch route quote credit snapshot hash does not bind its placement offer set")
	}
	retrievedAt, err := time.Parse(time.RFC3339Nano, value.RetrievedAt)
	if err != nil {
		return errors.New("launch route quote retrieval time is invalid")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, value.ExpiresAt)
	if err != nil || !retrievedAt.Before(expiresAt) {
		return errors.New("launch route quote expiry is invalid")
	}
	return nil
}

func aggregateLaunchCreditStatus(statuses []string) string {
	verified := false
	advisory := false
	for _, status := range statuses {
		switch status {
		case LaunchCreditUnknown:
			return LaunchCreditUnknown
		case LaunchCreditAdvisory:
			advisory = true
		case LaunchCreditVerified:
			verified = true
		}
	}
	if verified {
		return LaunchCreditVerified
	}
	if advisory {
		return LaunchCreditAdvisory
	}
	return LaunchCreditNone
}

func ValidateLaunchResourceGraph(value LaunchResourceGraph) error {
	if value.SchemaVersion != LaunchResourceGraphSchemaVersion || value.ResourceGraphID == "" || value.TenantID == "" || value.WorkspaceID == "" || value.MissionID == "" || len(value.Nodes) == 0 {
		return errors.New("launch resource graph identity or nodes are incomplete")
	}
	nodes := make(map[string]struct{}, len(value.Nodes))
	previous := ""
	for _, node := range value.Nodes {
		if node.ResourceID == "" || node.ResourceID <= previous || node.PlacementID == "" || node.WorkloadNodeID == "" || node.ResourceKind == "" || !launchLifecycleClassKnown(node.LifecycleClass) || !validLaunchSHA256(node.DesiredStateHash) || !validLaunchSHA256(node.OwnershipTagHash) {
			return errors.New("launch resource graph nodes must be complete, unique, and sorted")
		}
		previous = node.ResourceID
		nodes[node.ResourceID] = struct{}{}
	}
	previous = ""
	for _, edge := range value.Edges {
		key := launchTupleKey(edge.FromResourceID, edge.ToResourceID, edge.Relationship)
		if key <= previous || edge.Relationship == "" {
			return errors.New("launch resource graph edges must be complete, unique, and sorted")
		}
		previous = key
		if _, ok := nodes[edge.FromResourceID]; !ok {
			return errors.New("launch resource graph edge references an unknown source")
		}
		if _, ok := nodes[edge.ToResourceID]; !ok {
			return errors.New("launch resource graph edge references an unknown target")
		}
	}
	return nil
}

func ValidateLaunchProviderPayloadSet(value LaunchProviderPayloadSet) error {
	if value.SchemaVersion != LaunchProviderPayloadSetSchemaVersion || value.PayloadSetID == "" || value.TenantID == "" || value.WorkspaceID == "" || value.MissionID == "" || len(value.Entries) == 0 {
		return errors.New("launch provider payload set identity or entries are incomplete")
	}
	previous := ""
	for _, entry := range value.Entries {
		key := launchTupleKey(entry.PlacementID, entry.EffectID, entry.ProviderActionURN)
		if entry.PlacementID == "" || entry.EffectID == "" || entry.ProviderActionURN == "" || key <= previous || !validLaunchSHA256(entry.PayloadHash) {
			return errors.New("launch provider payload entries must be complete, unique, and sorted")
		}
		previous = key
		if !launchEffectIsProviderMutation(entry.EffectID) {
			return fmt.Errorf("launch provider payload effect %s is not a provider mutation", entry.EffectID)
		}
	}
	return nil
}

func ValidateLaunchBlueprint(value LaunchBlueprint) error {
	if value.SchemaVersion != LaunchBlueprintSchemaVersion || value.PortableVocabularyVersion != LaunchPortableVocabularyVersion || !launchBlueprintIDPattern.MatchString(value.BlueprintID) || !value.SourceReconnectRequired || !value.ProviderSelectionRequired || len(value.Nodes) == 0 {
		return errors.New("launch blueprint identity or clean-room reconnect flags are invalid")
	}
	nodes := make(map[string]struct{}, len(value.Nodes))
	previous := ""
	for _, node := range value.Nodes {
		if !launchBlueprintNodeIDPattern.MatchString(node.NodeID) || node.NodeID <= previous || !launchLifecycleClassKnown(node.LifecycleClass) {
			return errors.New("launch blueprint nodes must be complete, unique, and sorted")
		}
		if _, ok := launchPortableWorkloadKinds[node.Kind]; !ok {
			return errors.New("launch blueprint has a non-portable workload kind")
		}
		if err := validateLaunchPortableValues(node.RequiredCapabilities, "blueprint required capabilities", launchPortableCapabilities, true); err != nil {
			return err
		}
		previous = node.NodeID
		nodes[node.NodeID] = struct{}{}
	}
	previous = ""
	for _, edge := range value.Edges {
		key := launchTupleKey(edge.FromNodeID, edge.ToNodeID, edge.Relationship)
		if key <= previous {
			return errors.New("launch blueprint edges must be unique and sorted")
		}
		previous = key
		if _, ok := nodes[edge.FromNodeID]; !ok {
			return errors.New("launch blueprint edge references unknown source node")
		}
		if _, ok := nodes[edge.ToNodeID]; !ok {
			return errors.New("launch blueprint edge references unknown target node")
		}
		if _, ok := launchPortableRelationships[edge.Relationship]; !ok {
			return errors.New("launch blueprint edge relationship is not portable")
		}
	}
	if !launchCurrencyPattern.MatchString(value.Constraints.MaximumGrossCurrency) || value.Constraints.MaximumGrossMinor < 0 {
		return errors.New("launch blueprint gross constraint is invalid")
	}
	if err := validateSortedUniqueOptional(value.Constraints.AllowedJurisdictions, "blueprint allowed jurisdictions"); err != nil {
		return err
	}
	for _, jurisdiction := range value.Constraints.AllowedJurisdictions {
		if len(jurisdiction) != 2 || jurisdiction[0] < 'A' || jurisdiction[0] > 'Z' || jurisdiction[1] < 'A' || jurisdiction[1] > 'Z' {
			return errors.New("launch blueprint contains a non-portable jurisdiction")
		}
	}
	for name, valuesAndVocabulary := range map[string]struct {
		values     []string
		vocabulary map[string]struct{}
	}{
		"blueprint required residency tags":     {value.Constraints.RequiredResidencyTags, launchPortableResidencyTags},
		"blueprint allowed commitment terms":    {value.Constraints.AllowedCommitmentTerms, launchPortableCommitmentTerms},
		"blueprint required route capabilities": {value.Constraints.RequiredRouteCapabilities, launchPortableCapabilities},
	} {
		if err := validateLaunchPortableValues(valuesAndVocabulary.values, name, valuesAndVocabulary.vocabulary, false); err != nil {
			return err
		}
	}
	identity, err := DeriveLaunchBlueprintID(value)
	if err != nil || !launchConstantEqual(value.BlueprintID, identity) {
		return errors.New("launch blueprint identity does not bind its sanitized content")
	}
	return nil
}

// ProjectLaunchBlueprint removes all source, tenancy, provider, account,
// approval, and evidence identities. Node IDs are replaced with deterministic
// ordinal IDs, arbitrary semantic tokens are rejected, and the blueprint ID is
// derived from the sanitized projection rather than accepted from a caller.
func ProjectLaunchBlueprint(graph LaunchWorkloadGraph, constraints LaunchConstraintSet) (LaunchBlueprint, error) {
	if err := ValidateLaunchWorkloadGraph(graph); err != nil {
		return LaunchBlueprint{}, err
	}
	if err := ValidateLaunchConstraintSet(constraints); err != nil {
		return LaunchBlueprint{}, err
	}
	remap := make(map[string]string, len(graph.Nodes))
	blueprint := LaunchBlueprint{
		SchemaVersion: LaunchBlueprintSchemaVersion, PortableVocabularyVersion: LaunchPortableVocabularyVersion,
		SourceReconnectRequired: true, ProviderSelectionRequired: true,
		Nodes: make([]LaunchBlueprintNode, 0, len(graph.Nodes)),
		Edges: make([]LaunchBlueprintEdge, 0, len(graph.Edges)),
		Constraints: LaunchBlueprintConstraint{
			MaximumGrossCurrency: constraints.MaximumGrossCurrency, MaximumGrossMinor: constraints.MaximumGrossMinor,
			AllowedJurisdictions:      append([]string{}, constraints.AllowedJurisdictions...),
			RequiredResidencyTags:     append([]string{}, constraints.RequiredResidencyTags...),
			AllowedCommitmentTerms:    append([]string{}, constraints.AllowedCommitmentTerms...),
			RequiredRouteCapabilities: append([]string{}, constraints.RequiredRouteCapabilities...),
		},
	}
	for index, node := range graph.Nodes {
		if node.Deployability != LaunchAnalysisSupported {
			return LaunchBlueprint{}, fmt.Errorf("launch blueprint cannot project unresolved workload node %s", node.NodeID)
		}
		id := fmt.Sprintf("node-%04d", index+1)
		remap[node.NodeID] = id
		blueprint.Nodes = append(blueprint.Nodes, LaunchBlueprintNode{
			NodeID: id, Kind: node.Kind, LifecycleClass: node.LifecycleClass,
			RequiredCapabilities: append([]string(nil), node.RequiredCapabilities...),
		})
	}
	for _, edge := range graph.Edges {
		blueprint.Edges = append(blueprint.Edges, LaunchBlueprintEdge{
			FromNodeID: remap[edge.FromNodeID], ToNodeID: remap[edge.ToNodeID], Relationship: edge.Relationship,
		})
	}
	identity, err := DeriveLaunchBlueprintID(blueprint)
	if err != nil {
		return LaunchBlueprint{}, err
	}
	blueprint.BlueprintID = identity
	if err := ValidateLaunchBlueprint(blueprint); err != nil {
		return LaunchBlueprint{}, err
	}
	return blueprint, nil
}

// DeriveLaunchResourceSubsetHash binds one placement to only the resources it
// owns. Route producers use the same canonical projection as the verifier.
func DeriveLaunchResourceSubsetHash(graph LaunchResourceGraph, placementID string) (string, error) {
	nodes := make([]LaunchResourceNode, 0)
	nodeIDs := map[string]struct{}{}
	for _, node := range graph.Nodes {
		if node.PlacementID == placementID {
			nodes = append(nodes, node)
			nodeIDs[node.ResourceID] = struct{}{}
		}
	}
	edges := make([]LaunchResourceEdge, 0)
	for _, edge := range graph.Edges {
		_, from := nodeIDs[edge.FromResourceID]
		_, to := nodeIDs[edge.ToResourceID]
		if from && to {
			edges = append(edges, edge)
		}
	}
	return deriveLaunchCanonicalHash(struct {
		PlacementID string               `json:"placement_id"`
		Nodes       []LaunchResourceNode `json:"nodes"`
		Edges       []LaunchResourceEdge `json:"edges"`
	}{PlacementID: placementID, Nodes: nodes, Edges: edges}, "resource subset")
}

// DeriveLaunchProviderPayloadSubsetHash binds one placement to its exact set of
// connector requests without embedding provider payloads in the route plan.
func DeriveLaunchProviderPayloadSubsetHash(payloads LaunchProviderPayloadSet, placementID string) (string, error) {
	entries := make([]LaunchProviderPayloadEntry, 0)
	for _, entry := range payloads.Entries {
		if entry.PlacementID == placementID {
			entries = append(entries, entry)
		}
	}
	return deriveLaunchCanonicalHash(struct {
		PlacementID string                       `json:"placement_id"`
		Entries     []LaunchProviderPayloadEntry `json:"entries"`
	}{PlacementID: placementID, Entries: entries}, "provider payload subset")
}

func validateSortedUniqueOptional(values []string, name string) error {
	if len(values) == 0 {
		return nil
	}
	return validateSortedUniqueNonEmpty(values, name)
}

func validateLaunchPortableValues(values []string, name string, vocabulary map[string]struct{}, required bool) error {
	var err error
	if required {
		err = validateSortedUniqueNonEmpty(values, name)
	} else {
		err = validateSortedUniqueOptional(values, name)
	}
	if err != nil {
		return err
	}
	for _, value := range values {
		if _, ok := vocabulary[value]; !ok {
			return fmt.Errorf("%s contains a non-portable value", name)
		}
	}
	return nil
}

func addLaunchMinor(left, right int64) (int64, bool) {
	if left < 0 || right < 0 || left > math.MaxInt64-right {
		return 0, false
	}
	return left + right, true
}

func containsLaunchSorted(values []string, wanted string) bool {
	index := sort.SearchStrings(values, wanted)
	return index < len(values) && values[index] == wanted
}
