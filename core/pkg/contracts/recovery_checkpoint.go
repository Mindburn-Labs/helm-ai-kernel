package contracts

// This is a capture-evidence contract, not a checkpoint producer, persistence
// receipt or authorization to back up, restore, dispatch or resume work.
import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

const (
	RecoveryCheckpointSchemaV1                = "helm.provider-recovery-checkpoint.v1"
	RecoveryCheckpointPayloadType             = "application/vnd.helm.provider-recovery-checkpoint.v1+json"
	RecoveryCheckpointPurpose                 = "provider-recovery-checkpoint"
	RecoveryCheckpointMaxPayloadBytes         = 256 << 10
	RecoveryCheckpointMaxEnvelopeBytes        = 512 << 10
	RecoveryCheckpointMaxContentBytes         = 64 << 20
	RecoveryCheckpointMaxInteger       uint64 = 9007199254740991
)

var ErrRecoveryCheckpointInvalid = errors.New("invalid recovery checkpoint contract")

// All wire fields are required, including explicit empty arrays. There are no
// unsigned extension fields, credential values, content bodies or locators.
type RecoveryCheckpointDescriptor struct {
	SchemaVersion  string                           `json:"schema_version"`
	Purpose        string                           `json:"purpose"`
	Scope          RecoveryCheckpointScope          `json:"scope"`
	Producer       RecoveryCheckpointProducer       `json:"producer"`
	Native         RecoveryCheckpointNative         `json:"native"`
	Snapshot       RecoveryCheckpointSnapshot       `json:"snapshot"`
	Capture        RecoveryCheckpointCapture        `json:"capture"`
	Installed      RecoveryCheckpointInstalled      `json:"installed"`
	Participants   []RecoveryCheckpointParticipant  `json:"participants"`
	EvidencePrefix RecoveryCheckpointEvidencePrefix `json:"evidence_prefix"`
}

type RecoveryCheckpointScope struct {
	TenantID       string `json:"tenant_id"`
	WorkspaceID    string `json:"workspace_id"`
	OrganizationID string `json:"organization_id"`
	OperationID    string `json:"operation_id"`
	InstallationID string `json:"installation_id"`
	Generation     uint64 `json:"generation"`
}

type RecoveryCheckpointProducer struct {
	Issuer            string `json:"issuer"`
	Subject           string `json:"subject"`
	SourceRevision    string `json:"source_revision"`
	ImageDigest       string `json:"image_digest"`
	PodUID            string `json:"pod_uid"`
	ServiceAccountUID string `json:"service_account_uid"`
	CohortDigest      string `json:"cohort_digest"`
}

type RecoveryCheckpointNative struct {
	CPVersionID              string   `json:"cp_version_id"`
	AuthorityVersionID       string   `json:"authority_version_id"`
	CoveredVersionIDs        []string `json:"covered_version_ids"`
	PlanDigest               string   `json:"plan_digest"`
	CutoffWatermark          string   `json:"cutoff_watermark"`
	AuthorityRevision        uint64   `json:"authority_revision"`
	InventoryCount           uint64   `json:"inventory_count"`
	UnresolvedCount          uint64   `json:"unresolved_count"`
	BeforeInventoryWatermark string   `json:"before_inventory_watermark"`
	AfterInventoryWatermark  string   `json:"after_inventory_watermark"`
}

// CustodyID is an opaque identifier. This contract does not authenticate a
// caller-supplied storage receipt or prove that bytes have been retained.
type RecoveryCheckpointSnapshot struct {
	Digest               string `json:"digest"`
	ByteLength           uint64 `json:"byte_length"`
	CustodyID            string `json:"custody_id"`
	SchemaDigest         string `json:"schema_digest"`
	CaptureCatalogDigest string `json:"capture_catalog_digest"`
}

type RecoveryCheckpointCapture struct {
	OrganizationRowVersion uint64                            `json:"organization_row_version"`
	SpecDigest             string                            `json:"spec_digest"`
	WorkRevisionDigest     string                            `json:"work_revision_digest"`
	RunEventHeadsDigest    string                            `json:"run_event_heads_digest"`
	EpisodeHeadsDigest     string                            `json:"episode_heads_digest"`
	LeaseIdentityDigest    string                            `json:"lease_identity_digest"`
	QueueIntentDigest      string                            `json:"queue_intent_digest"`
	Sections               []RecoveryCheckpointSection       `json:"sections"`
	RealtimeContext        RecoveryCheckpointRealtimeContext `json:"realtime_context"`
}

type RecoveryCheckpointSection struct {
	Name     string `json:"name"`
	RowCount uint64 `json:"row_count"`
	Digest   string `json:"digest"`
}

// This cursor is shared-workspace context, not organization restore authority.
type RecoveryCheckpointRealtimeContext struct {
	StreamID string `json:"stream_id"`
	Head     uint64 `json:"head"`
	Floor    uint64 `json:"floor"`
}

type RecoveryCheckpointInstalled struct {
	CohortDigest            string                        `json:"cohort_digest"`
	ClusterCADigest         string                        `json:"cluster_ca_digest"`
	PublicTrustDigest       string                        `json:"public_trust_digest"`
	BeforeObservationDigest string                        `json:"before_observation_digest"`
	AfterObservationDigest  string                        `json:"after_observation_digest"`
	RuntimeComponents       []RecoveryCheckpointComponent `json:"runtime_components"`
	Console                 RecoveryCheckpointComponent   `json:"console"`
}

type RecoveryCheckpointComponent struct {
	Name              string   `json:"name"`
	SourceRepository  string   `json:"source_repository"`
	SourceRevision    string   `json:"source_revision"`
	ImageDigest       string   `json:"image_digest"`
	Platform          string   `json:"platform"`
	NamespaceUID      string   `json:"namespace_uid"`
	WorkloadUID       string   `json:"workload_uid"`
	ServiceUID        string   `json:"service_uid"`
	ServiceAccountUID string   `json:"service_account_uid"`
	PodUIDs           []string `json:"pod_uids"`
	TrustRole         string   `json:"trust_role"`
	ObservationDigest string   `json:"observation_digest"`
}

// ContentDigest authenticates the owner's declared content-copy/reference
// projection, not an ETag, bucket version or independent store readback.
type RecoveryCheckpointParticipant struct {
	StoreID         string `json:"store_id"`
	Kind            string `json:"kind"`
	BeforeWatermark string `json:"before_watermark"`
	AfterWatermark  string `json:"after_watermark"`
	EntryCount      uint64 `json:"entry_count"`
	ContentDigest   string `json:"content_digest"`
}

type RecoveryCheckpointEvidencePrefix struct {
	Sequence       uint64 `json:"sequence"`
	EnvelopeDigest string `json:"envelope_digest"`
}

// The envelope contains only DSSE transport fields. KeyID is a lookup hint;
// no key material or self-declared trust policy is accepted here.
type RecoveryCheckpointEnvelope struct {
	PayloadType string                        `json:"payloadType"`
	Payload     string                        `json:"payload"`
	Signatures  []RecoveryCheckpointSignature `json:"signatures"`
}

type RecoveryCheckpointSignature struct {
	KeyID     string `json:"keyid"`
	Signature string `json:"sig"`
}

var recoveryCheckpointToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var recoveryCheckpointSection = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
var recoveryCheckpointRepository = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$`)
var recoveryCheckpointRevision = regexp.MustCompile(`^[0-9a-f]{40}$`)
var recoveryCheckpointDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func checkpointInvalid(message string) error {
	return fmt.Errorf("%w: %s", ErrRecoveryCheckpointInvalid, message)
}
func checkpointUUID(value string) bool {
	// The schema requires only nonzero, lowercase, hyphenated 128-bit IDs.
	// Do not add UUID version/variant restrictions or pull hardware/network
	// discovery into the shared contracts dependency graph to parse bytes.
	if len(value) != 36 {
		return false
	}
	nonzero := false
	for i := range len(value) {
		b := value[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if b != '-' {
				return false
			}
			continue
		}
		if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f') {
			return false
		}
		nonzero = nonzero || b != '0'
	}
	return nonzero
}
func checkpointInteger(value uint64) bool  { return value <= RecoveryCheckpointMaxInteger }
func checkpointPositive(value uint64) bool { return value > 0 && checkpointInteger(value) }
func checkpointIssuer(value string) bool {
	u, err := url.Parse(value)
	if err != nil || !utf8.ValidString(value) || len(value) > 512 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.ForceQuery || strings.ContainsAny(value, "?#") || strings.HasSuffix(u.Host, ":") {
		return false
	}
	if u.Port() != "" {
		port, err := strconv.Atoi(u.Port())
		return err == nil && port > 0 && port <= 65535
	}
	return true
}
func checkpointDigests(values ...string) bool {
	for _, value := range values {
		if !recoveryCheckpointDigest.MatchString(value) {
			return false
		}
	}
	return true
}
func checkpointUUIDs(values []string, max int) bool {
	if len(values) == 0 || len(values) > max {
		return false
	}
	for i, value := range values {
		if !checkpointUUID(value) || i > 0 && values[i-1] >= value {
			return false
		}
	}
	return true
}

func (d RecoveryCheckpointDescriptor) Validate() error {
	if d.SchemaVersion != RecoveryCheckpointSchemaV1 || d.Purpose != RecoveryCheckpointPurpose {
		return checkpointInvalid("unsupported schema or purpose")
	}
	s := d.Scope
	if !checkpointUUID(s.TenantID) || !checkpointUUID(s.WorkspaceID) || !checkpointUUID(s.OrganizationID) || !checkpointUUID(s.OperationID) || !recoveryCheckpointToken.MatchString(s.InstallationID) || !checkpointPositive(s.Generation) {
		return checkpointInvalid("scope")
	}
	p := d.Producer
	if !checkpointIssuer(p.Issuer) || p.Subject != "spiffe://helm/control-plane" || !recoveryCheckpointRevision.MatchString(p.SourceRevision) || !checkpointUUID(p.PodUID) || !checkpointUUID(p.ServiceAccountUID) || !checkpointDigests(p.ImageDigest, p.CohortDigest) {
		return checkpointInvalid("producer")
	}
	n := d.Native
	if !checkpointUUID(n.CPVersionID) || !checkpointUUID(n.AuthorityVersionID) || !checkpointUUIDs(n.CoveredVersionIDs, 4096) || !slices.Contains(n.CoveredVersionIDs, n.CPVersionID) || !slices.Contains(n.CoveredVersionIDs, n.AuthorityVersionID) || !checkpointDigests(n.PlanDigest, n.CutoffWatermark, n.BeforeInventoryWatermark, n.AfterInventoryWatermark) || n.BeforeInventoryWatermark != n.AfterInventoryWatermark || !checkpointPositive(n.AuthorityRevision) || !checkpointInteger(n.InventoryCount) || n.UnresolvedCount != 0 {
		return checkpointInvalid("native binding or unsettled inventory")
	}
	v := d.Snapshot
	if !checkpointDigests(v.Digest, v.SchemaDigest, v.CaptureCatalogDigest) || v.ByteLength == 0 || v.ByteLength > RecoveryCheckpointMaxContentBytes || !checkpointUUID(v.CustodyID) {
		return checkpointInvalid("snapshot")
	}
	c := d.Capture
	if !checkpointPositive(c.OrganizationRowVersion) || !checkpointDigests(c.SpecDigest, c.WorkRevisionDigest, c.RunEventHeadsDigest, c.EpisodeHeadsDigest, c.LeaseIdentityDigest, c.QueueIntentDigest) || len(c.Sections) == 0 || len(c.Sections) > 128 || !checkpointUUID(c.RealtimeContext.StreamID) || !checkpointInteger(c.RealtimeContext.Head) || c.RealtimeContext.Floor > c.RealtimeContext.Head {
		return checkpointInvalid("lifecycle capture")
	}
	for i, section := range c.Sections {
		if !recoveryCheckpointSection.MatchString(section.Name) || !checkpointInteger(section.RowCount) || !checkpointDigests(section.Digest) || i > 0 && c.Sections[i-1].Name >= section.Name {
			return checkpointInvalid("unordered or invalid capture sections")
		}
	}
	i := d.Installed
	if !checkpointDigests(i.CohortDigest, i.ClusterCADigest, i.PublicTrustDigest, i.BeforeObservationDigest, i.AfterObservationDigest) || i.CohortDigest != p.CohortDigest || i.BeforeObservationDigest != i.AfterObservationDigest || len(i.RuntimeComponents) != 7 || i.Console.Name != "console" {
		return checkpointInvalid("complete installed cohort")
	}
	names := []string{"certification", "control_plane", "data_plane", "evidence_signer", "kernel", "sandbox_runner", "workload_identity"}
	for index, component := range i.RuntimeComponents {
		if component.Name != names[index] || component.validate() != nil {
			return checkpointInvalid("runtime component")
		}
		if component.Name == "control_plane" && (component.SourceRevision != p.SourceRevision || component.ImageDigest != p.ImageDigest || component.ServiceAccountUID != p.ServiceAccountUID || !slices.Contains(component.PodUIDs, p.PodUID)) {
			return checkpointInvalid("producer differs from installed control plane")
		}
	}
	if err := i.Console.validate(); err != nil {
		return err
	}
	if len(d.Participants) < 3 || len(d.Participants) > 64 {
		return checkpointInvalid("complete participant set")
	}
	kinds := map[string]int{}
	for index, participant := range d.Participants {
		if !recoveryCheckpointToken.MatchString(participant.StoreID) || index > 0 && d.Participants[index-1].StoreID >= participant.StoreID || !checkpointDigests(participant.BeforeWatermark, participant.AfterWatermark, participant.ContentDigest) || participant.BeforeWatermark != participant.AfterWatermark || !checkpointInteger(participant.EntryCount) {
			return checkpointInvalid("participant watermark")
		}
		if participant.Kind == "native_authority" && (participant.BeforeWatermark != n.BeforeInventoryWatermark || participant.EntryCount != n.InventoryCount || participant.ContentDigest != n.BeforeInventoryWatermark) {
			return checkpointInvalid("native participant differs from inventory")
		}
		switch participant.Kind {
		case "control_plane", "native_authority", "verified_content_copy":
			kinds[participant.Kind]++
		default:
			return checkpointInvalid("unsupported participant kind")
		}
	}
	if kinds["control_plane"] != 1 || kinds["native_authority"] != 1 || kinds["verified_content_copy"] < 1 {
		return checkpointInvalid("missing participating store")
	}
	if !checkpointInteger(d.EvidencePrefix.Sequence) || !checkpointDigests(d.EvidencePrefix.EnvelopeDigest) {
		return checkpointInvalid("evidence prefix")
	}
	return nil
}

func (c RecoveryCheckpointComponent) validate() error {
	if !recoveryCheckpointRepository.MatchString(c.SourceRepository) || !recoveryCheckpointRevision.MatchString(c.SourceRevision) || !checkpointDigests(c.ImageDigest, c.ObservationDigest) || c.Platform != "linux/amd64" && c.Platform != "linux/arm64" || !checkpointUUID(c.NamespaceUID) || !checkpointUUID(c.WorkloadUID) || !checkpointUUID(c.ServiceUID) || !checkpointUUID(c.ServiceAccountUID) || !checkpointUUIDs(c.PodUIDs, 64) {
		return checkpointInvalid("component identity")
	}
	switch c.TrustRole {
	case "none", "authority", "signer":
	default:
		return checkpointInvalid("component trust role")
	}
	return nil
}

// EncodeRecoveryCheckpoint constructs deterministic canonical bytes. Every
// string is validated before JCS, whose legacy pre-marshal replaces bad UTF-8.
func EncodeRecoveryCheckpoint(d RecoveryCheckpointDescriptor) ([]byte, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	if err := checkpointUTF8(reflect.ValueOf(d)); err != nil {
		return nil, err
	}
	raw, err := canonicalize.JCS(d)
	if err != nil || len(raw) > RecoveryCheckpointMaxPayloadBytes {
		return nil, checkpointInvalid("canonical descriptor size or encoding")
	}
	return raw, nil
}

func DecodeRecoveryCheckpoint(raw []byte) (RecoveryCheckpointDescriptor, error) {
	var descriptor RecoveryCheckpointDescriptor
	if err := checkpointDecodeExact(raw, &descriptor, RecoveryCheckpointMaxPayloadBytes); err != nil {
		return descriptor, err
	}
	return descriptor, descriptor.Validate()
}

// VerifyRecoveryCheckpointContent checks supplied private bytes without storing,
// exporting or interpreting them. It establishes no custody or restore claim.
func VerifyRecoveryCheckpointContent(descriptor RecoveryCheckpointDescriptor, content []byte) error {
	if err := descriptor.Validate(); err != nil {
		return err
	}
	if uint64(len(content)) != descriptor.Snapshot.ByteLength || RecoveryCheckpointHash(content) != descriptor.Snapshot.Digest {
		return checkpointInvalid("private content length or digest")
	}
	return nil
}

// DecodeRecoveryCheckpointEnvelope checks transport syntax and encodings only.
// Cryptographic and externally pinned semantic trust require evidence verification.
func DecodeRecoveryCheckpointEnvelope(raw []byte) (RecoveryCheckpointEnvelope, []byte, []byte, error) {
	var envelope RecoveryCheckpointEnvelope
	if err := checkpointDecodeExact(raw, &envelope, RecoveryCheckpointMaxEnvelopeBytes); err != nil {
		return envelope, nil, nil, err
	}
	if envelope.PayloadType != RecoveryCheckpointPayloadType || len(envelope.Signatures) != 1 || !recoveryCheckpointToken.MatchString(envelope.Signatures[0].KeyID) {
		return envelope, nil, nil, checkpointInvalid("DSSE type, signature count or key hint")
	}
	payload, err := checkpointBase64(envelope.Payload)
	if err != nil || len(payload) == 0 || len(payload) > RecoveryCheckpointMaxPayloadBytes {
		return envelope, nil, nil, checkpointInvalid("DSSE payload encoding")
	}
	signature, err := checkpointBase64(envelope.Signatures[0].Signature)
	if err != nil || len(signature) != 64 {
		return envelope, nil, nil, checkpointInvalid("DSSE signature encoding")
	}
	return envelope, payload, signature, nil
}

func checkpointBase64(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, checkpointInvalid("noncanonical base64")
	}
	return decoded, nil
}

func RecoveryCheckpointHash(raw []byte) string {
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func checkpointUTF8(value reflect.Value) error {
	switch value.Kind() {
	case reflect.String:
		if !utf8.ValidString(value.String()) {
			return checkpointInvalid("invalid UTF-8")
		}
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			if err := checkpointUTF8(value.Field(i)); err != nil {
				return err
			}
		}
	case reflect.Slice:
		for i := 0; i < value.Len(); i++ {
			if err := checkpointUTF8(value.Index(i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkpointDecodeExact(raw []byte, into any, maximum int) error {
	if len(raw) == 0 || len(raw) > maximum || !utf8.Valid(raw) {
		return checkpointInvalid("JSON size or UTF-8")
	}
	if err := checkpointSurrogates(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	nodes := 0
	if err := checkpointUnique(decoder, 0, &nodes); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return checkpointInvalid("trailing JSON")
	}
	if err := checkpointShape(raw, reflect.TypeOf(into).Elem()); err != nil {
		return err
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(into); err != nil {
		return checkpointInvalid("JSON field type or integer encoding")
	}
	return nil
}

func checkpointUnique(decoder *json.Decoder, depth int, nodes *int) error {
	*nodes++
	if depth > 24 || *nodes > 65536 {
		return checkpointInvalid("JSON structural bound")
	}
	token, err := decoder.Token()
	if err != nil {
		return checkpointInvalid("malformed JSON")
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return checkpointInvalid("object key")
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return checkpointInvalid("duplicate object key")
			}
			seen[name] = true
			if err := checkpointUnique(decoder, depth+1, nodes); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := checkpointUnique(decoder, depth+1, nodes); err != nil {
				return err
			}
		}
	default:
		return checkpointInvalid("unexpected delimiter")
	}
	if _, err := decoder.Token(); err != nil {
		return checkpointInvalid("unclosed JSON value")
	}
	return nil
}

// Exact tag comparison also rejects encoding/json's case-insensitive aliases.
func checkpointShape(raw []byte, shape reflect.Type) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return checkpointInvalid("null field")
	}
	switch shape.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil || len(fields) != shape.NumField() {
			return checkpointInvalid("missing or unknown object field")
		}
		for i := 0; i < shape.NumField(); i++ {
			field := shape.Field(i)
			value, ok := fields[field.Tag.Get("json")]
			if !ok {
				return checkpointInvalid("missing or nonexact field name")
			}
			if err := checkpointShape(value, field.Type); err != nil {
				return err
			}
		}
	case reflect.Slice:
		var values []json.RawMessage
		if json.Unmarshal(raw, &values) != nil || len(values) > 4096 {
			return checkpointInvalid("array type or bound")
		}
		for _, value := range values {
			if err := checkpointShape(value, shape.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}

// encoding/json replaces lone escaped UTF-16 surrogates. Refuse them before
// decoding so two distinct byte inputs cannot collapse into one application value.
func checkpointSurrogates(raw []byte) error {
	for i := 0; i < len(raw); i++ {
		if raw[i] != '"' {
			continue
		}
		for i++; i < len(raw) && raw[i] != '"'; i++ {
			if raw[i] != '\\' {
				continue
			}
			i++
			if i >= len(raw) {
				return checkpointInvalid("string escape")
			}
			if raw[i] != 'u' {
				continue
			}
			if i+4 >= len(raw) {
				return checkpointInvalid("unicode escape")
			}
			value, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
			if err != nil {
				return checkpointInvalid("unicode escape")
			}
			i += 4
			if value >= 0xdc00 && value <= 0xdfff {
				return checkpointInvalid("lone low surrogate")
			}
			if value < 0xd800 || value > 0xdbff {
				continue
			}
			if i+6 >= len(raw) || string(raw[i+1:i+3]) != `\u` {
				return checkpointInvalid("lone high surrogate")
			}
			low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return checkpointInvalid("invalid surrogate pair")
			}
			i += 6
		}
	}
	return nil
}
