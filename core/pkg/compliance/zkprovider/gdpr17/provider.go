package gdpr17

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	nativemimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

var (
	ErrMissingKey = errors.New("gdpr17 key material is required")
	ErrKeyExpired = errors.New("gdpr17 key material is expired")
)

type Event struct {
	Unix         int64 `json:"unix"`
	SubjectMatch bool  `json:"subject_match"`
}

type ProveRequest struct {
	PolicyID     string  `json:"policy_id"`
	ErasureUnix  int64   `json:"erasure_unix"`
	SubjectID    string  `json:"subject_id"`
	SubjectNonce string  `json:"subject_nonce"`
	Events       []Event `json:"events"`
}

type PublicSignals struct {
	CircuitID     uint64 `json:"circuit_id"`
	PolicyHash    string `json:"policy_hash"`
	ErasureUnix   int64  `json:"erasure_unix"`
	SubjectCommit string `json:"subject_commit"`
	TraceCommit   string `json:"trace_commit"`
}

type Proof struct {
	Scheme                  string        `json:"scheme"`
	CircuitVersion          string        `json:"circuit_version"`
	CreatedAt               time.Time     `json:"created_at"`
	VerifyingKeyFingerprint string        `json:"verifying_key_fingerprint"`
	PublicSignals           PublicSignals `json:"public_signals"`
	Proof                   []byte        `json:"proof"`
}

type KeyPair struct {
	ConstraintSystem constraint.ConstraintSystem
	ProvingKey       groth16.ProvingKey
	VerifyingKey     groth16.VerifyingKey
}

type Prover struct {
	cs constraint.ConstraintSystem
	pk groth16.ProvingKey
	vk groth16.VerifyingKey
}

type Verifier struct {
	vk groth16.VerifyingKey
}

type proverOptions struct {
	pk        groth16.ProvingKey
	vk        groth16.VerifyingKey
	pkPath    string
	vkPath    string
	expiresAt *time.Time
}

type verifierOptions struct {
	vk        groth16.VerifyingKey
	vkPath    string
	expiresAt *time.Time
}

type ProverOption func(*proverOptions)
type VerifierOption func(*verifierOptions)

func WithProvingKey(pk groth16.ProvingKey) ProverOption {
	return func(opts *proverOptions) {
		opts.pk = pk
	}
}

func WithVerifyingKeyForProofs(vk groth16.VerifyingKey) ProverOption {
	return func(opts *proverOptions) {
		opts.vk = vk
	}
}

func WithProvingKeyPath(path string, expiresAt ...time.Time) ProverOption {
	return func(opts *proverOptions) {
		opts.pkPath = path
		opts.expiresAt = optionalExpiry(expiresAt)
	}
}

func WithVerifyingKeyForProofsPath(path string, expiresAt ...time.Time) ProverOption {
	return func(opts *proverOptions) {
		opts.vkPath = path
		opts.expiresAt = optionalExpiry(expiresAt)
	}
}

func WithVerifyingKey(vk groth16.VerifyingKey) VerifierOption {
	return func(opts *verifierOptions) {
		opts.vk = vk
	}
}

func WithVerifyingKeyPath(path string, expiresAt ...time.Time) VerifierOption {
	return func(opts *verifierOptions) {
		opts.vkPath = path
		opts.expiresAt = optionalExpiry(expiresAt)
	}
}

func NewProver(options ...ProverOption) (*Prover, error) {
	opts := proverOptions{}
	for _, option := range options {
		option(&opts)
	}
	if err := checkExpiry(opts.expiresAt); err != nil {
		return nil, err
	}
	if opts.pk == nil && opts.pkPath != "" {
		pk, err := LoadProvingKey(opts.pkPath)
		if err != nil {
			return nil, err
		}
		opts.pk = pk
	}
	if opts.vk == nil && opts.vkPath != "" {
		vk, err := LoadVerifyingKey(opts.vkPath)
		if err != nil {
			return nil, err
		}
		opts.vk = vk
	}
	if opts.pk == nil {
		return nil, ErrMissingKey
	}

	cs, err := Compile()
	if err != nil {
		return nil, err
	}
	return &Prover{cs: cs, pk: opts.pk, vk: opts.vk}, nil
}

func NewVerifier(options ...VerifierOption) (*Verifier, error) {
	opts := verifierOptions{}
	for _, option := range options {
		option(&opts)
	}
	if err := checkExpiry(opts.expiresAt); err != nil {
		return nil, err
	}
	if opts.vk == nil && opts.vkPath != "" {
		vk, err := LoadVerifyingKey(opts.vkPath)
		if err != nil {
			return nil, err
		}
		opts.vk = vk
	}
	if opts.vk == nil {
		return nil, ErrMissingKey
	}
	return &Verifier{vk: opts.vk}, nil
}

func Compile() (constraint.ConstraintSystem, error) {
	return frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Circuit{})
}

func GenerateKeys() (*KeyPair, error) {
	cs, err := Compile()
	if err != nil {
		return nil, err
	}
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		return nil, err
	}
	return &KeyPair{ConstraintSystem: cs, ProvingKey: pk, VerifyingKey: vk}, nil
}

func (p *Prover) Prove(req ProveRequest) (*Proof, error) {
	assignment, signals, err := assignmentForRequest(req)
	if err != nil {
		return nil, err
	}
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("build witness: %w", err)
	}

	proof, err := groth16.Prove(p.cs, p.pk, witness)
	if err != nil {
		return nil, fmt.Errorf("prove gdpr17 circuit: %w", err)
	}
	proofBytes, err := SerializeProof(proof)
	if err != nil {
		return nil, err
	}

	var vkFingerprint string
	if p.vk != nil {
		vkFingerprint, err = KeyFingerprint(p.vk)
		if err != nil {
			return nil, err
		}
	}

	return &Proof{
		Scheme:                  Scheme,
		CircuitVersion:          CircuitVersion,
		CreatedAt:               time.Now().UTC(),
		VerifyingKeyFingerprint: vkFingerprint,
		PublicSignals:           signals,
		Proof:                   proofBytes,
	}, nil
}

func (v *Verifier) Verify(artifact *Proof) error {
	if artifact == nil {
		return errors.New("gdpr17 proof is nil")
	}
	if artifact.Scheme != Scheme {
		return fmt.Errorf("unsupported gdpr17 proof scheme %q", artifact.Scheme)
	}
	if artifact.CircuitVersion != CircuitVersion {
		return fmt.Errorf("unsupported gdpr17 circuit version %q", artifact.CircuitVersion)
	}
	if artifact.PublicSignals.CircuitID != CircuitID {
		return fmt.Errorf("unexpected gdpr17 circuit id %d", artifact.PublicSignals.CircuitID)
	}

	proof, err := DeserializeProof(artifact.Proof)
	if err != nil {
		return err
	}
	publicWitness, err := publicWitnessForSignals(artifact.PublicSignals)
	if err != nil {
		return err
	}
	return groth16.Verify(proof, v.vk, publicWitness)
}

func SerializeProof(proof groth16.Proof) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := proof.WriteTo(&buf); err != nil {
		return nil, fmt.Errorf("serialize gdpr17 proof: %w", err)
	}
	return buf.Bytes(), nil
}

func DeserializeProof(data []byte) (groth16.Proof, error) {
	proof := groth16.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(bytes.NewReader(data)); err != nil {
		return nil, fmt.Errorf("deserialize gdpr17 proof: %w", err)
	}
	return proof, nil
}

func MarshalProof(artifact *Proof) ([]byte, error) {
	return json.MarshalIndent(artifact, "", "  ")
}

func ParseProof(data []byte) (*Proof, error) {
	var artifact Proof
	if err := json.Unmarshal(data, &artifact); err != nil {
		return nil, err
	}
	return &artifact, nil
}

func WriteProofFile(path string, artifact *Proof) error {
	data, err := MarshalProof(artifact)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func ReadProofFile(path string) (*Proof, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseProof(data)
}

func WriteProvingKey(path string, pk groth16.ProvingKey) error {
	return writeKey(path, pk)
}

func WriteVerifyingKey(path string, vk groth16.VerifyingKey) error {
	return writeKey(path, vk)
}

func LoadProvingKey(path string) (groth16.ProvingKey, error) {
	pk := groth16.NewProvingKey(ecc.BN254)
	if err := readKey(path, pk); err != nil {
		return nil, err
	}
	return pk, nil
}

func LoadVerifyingKey(path string) (groth16.VerifyingKey, error) {
	vk := groth16.NewVerifyingKey(ecc.BN254)
	if err := readKey(path, vk); err != nil {
		return nil, err
	}
	return vk, nil
}

func KeyFingerprint(key interface {
	WriteTo(io.Writer) (int64, error)
}) (string, error) {
	var buf bytes.Buffer
	if _, err := key.WriteTo(&buf); err != nil {
		return "", err
	}
	sum := sha256.Sum256(buf.Bytes())
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func assignmentForRequest(req ProveRequest) (*Circuit, PublicSignals, error) {
	if err := validateRequest(req); err != nil {
		return nil, PublicSignals{}, err
	}

	policyHash, err := hashToField("policy", []byte(req.PolicyID))
	if err != nil {
		return nil, PublicSignals{}, err
	}
	subjectScalar, err := hashToField("subject", []byte(req.SubjectID))
	if err != nil {
		return nil, PublicSignals{}, err
	}
	subjectNonce, err := hashToField("subject-nonce", []byte(req.SubjectNonce))
	if err != nil {
		return nil, PublicSignals{}, err
	}
	subjectCommit, err := mimcHashElements(subjectScalar, subjectNonce)
	if err != nil {
		return nil, PublicSignals{}, err
	}

	var eventActive [MaxEvents]frontend.Variable
	var eventSubjectMatch [MaxEvents]frontend.Variable
	var eventUnix [MaxEvents]frontend.Variable
	traceInputs := make([]fr.Element, 0, MaxEvents*3)
	for i := 0; i < MaxEvents; i++ {
		active := uint64(0)
		subjectMatch := uint64(0)
		ts := uint64(0)
		if i < len(req.Events) {
			active = 1
			if req.Events[i].SubjectMatch {
				subjectMatch = 1
			}
			ts = uint64(req.Events[i].Unix)
		}
		eventActive[i] = active
		eventSubjectMatch[i] = subjectMatch
		eventUnix[i] = ts
		traceInputs = append(traceInputs, fieldFromUint64(active), fieldFromUint64(subjectMatch), fieldFromUint64(ts))
	}
	traceCommit, err := mimcHashElements(traceInputs...)
	if err != nil {
		return nil, PublicSignals{}, err
	}

	signals := PublicSignals{
		CircuitID:     CircuitID,
		PolicyHash:    fieldDecimal(policyHash),
		ErasureUnix:   req.ErasureUnix,
		SubjectCommit: fieldDecimal(subjectCommit),
		TraceCommit:   fieldDecimal(traceCommit),
	}

	assignment := &Circuit{
		CircuitID:         CircuitID,
		PolicyHash:        elemBig(policyHash),
		ErasureUnix:       req.ErasureUnix,
		SubjectCommit:     elemBig(subjectCommit),
		TraceCommit:       elemBig(traceCommit),
		SubjectScalar:     elemBig(subjectScalar),
		SubjectNonce:      elemBig(subjectNonce),
		EventActive:       eventActive,
		EventSubjectMatch: eventSubjectMatch,
		EventUnix:         eventUnix,
	}
	return assignment, signals, nil
}

func publicWitnessForSignals(signals PublicSignals) (witness.Witness, error) {
	if signals.CircuitID != CircuitID {
		return nil, fmt.Errorf("unexpected gdpr17 circuit id %d", signals.CircuitID)
	}
	policyHash, err := decimalToBig(signals.PolicyHash)
	if err != nil {
		return nil, fmt.Errorf("parse policy hash: %w", err)
	}
	subjectCommit, err := decimalToBig(signals.SubjectCommit)
	if err != nil {
		return nil, fmt.Errorf("parse subject commitment: %w", err)
	}
	traceCommit, err := decimalToBig(signals.TraceCommit)
	if err != nil {
		return nil, fmt.Errorf("parse trace commitment: %w", err)
	}

	assignment := &Circuit{
		CircuitID:     signals.CircuitID,
		PolicyHash:    policyHash,
		ErasureUnix:   signals.ErasureUnix,
		SubjectCommit: subjectCommit,
		TraceCommit:   traceCommit,
	}
	return frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
}

func validateRequest(req ProveRequest) error {
	if req.PolicyID == "" {
		return errors.New("policy id is required")
	}
	if req.SubjectID == "" {
		return errors.New("subject id is required")
	}
	if req.SubjectNonce == "" {
		return errors.New("subject nonce is required")
	}
	if req.ErasureUnix < 0 || req.ErasureUnix > maxUnixSeconds {
		return fmt.Errorf("erasure unix must be between 0 and %d", maxUnixSeconds)
	}
	if len(req.Events) > MaxEvents {
		return fmt.Errorf("gdpr17 supports at most %d events", MaxEvents)
	}
	for i, event := range req.Events {
		if event.Unix <= 0 || event.Unix > maxUnixSeconds {
			return fmt.Errorf("event %d unix must be between 1 and %d", i, maxUnixSeconds)
		}
	}
	return nil
}

func hashToField(label string, data []byte) (fr.Element, error) {
	values, err := fr.Hash(data, []byte("HELM-GDPR17-"+label), 1)
	if err != nil {
		return fr.Element{}, err
	}
	return values[0], nil
}

func mimcHashElements(elements ...fr.Element) (fr.Element, error) {
	hasher := nativemimc.NewMiMC()
	for _, element := range elements {
		bytes := element.Bytes()
		if _, err := hasher.Write(bytes[:]); err != nil {
			return fr.Element{}, err
		}
	}
	sum := hasher.Sum(nil)
	var out fr.Element
	if err := out.SetBytesCanonical(sum); err != nil {
		return fr.Element{}, err
	}
	return out, nil
}

func fieldFromUint64(value uint64) fr.Element {
	var out fr.Element
	out.SetUint64(value)
	return out
}

func elemBig(element fr.Element) *big.Int {
	var out big.Int
	element.BigInt(&out)
	return &out
}

func fieldDecimal(element fr.Element) string {
	return elemBig(element).String()
}

func decimalToBig(value string) (*big.Int, error) {
	out, ok := new(big.Int).SetString(value, 10)
	if !ok {
		return nil, fmt.Errorf("invalid decimal field element %q", value)
	}
	if out.Sign() < 0 || out.Cmp(fr.Modulus()) >= 0 {
		return nil, fmt.Errorf("field element out of range")
	}
	return out, nil
}

func writeKey(path string, key interface {
	WriteTo(io.Writer) (int64, error)
}) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = key.WriteTo(file)
	return err
}

func readKey(path string, key interface {
	ReadFrom(io.Reader) (int64, error)
}) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = key.ReadFrom(file)
	return err
}

func optionalExpiry(values []time.Time) *time.Time {
	if len(values) == 0 {
		return nil
	}
	value := values[0]
	return &value
}

func checkExpiry(expiresAt *time.Time) error {
	if expiresAt == nil {
		return nil
	}
	if !time.Now().UTC().Before(expiresAt.UTC()) {
		return ErrKeyExpired
	}
	return nil
}
