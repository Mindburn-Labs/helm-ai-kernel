package zk

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// SafetyAssertion defines the constraints a tool proposal must satisfy
// to be verified as safe for execution on the sovereign host.
type SafetyAssertion struct {
	BannedImports []string `json:"banned_imports"`
	SandboxPaths  []string `json:"sandbox_paths"`
	AllowNetwork  bool     `json:"allow_network"`
	MaxFileSize   int64    `json:"max_file_size"`
}

// SafetyJournal represents the public output of the zkVM guest safety execution.
// It is serialized into the receipt's journal field and verified on-chain or on-host.
type SafetyJournal struct {
	ProposalHash []byte          `json:"proposal_hash"`
	Assertions   SafetyAssertion `json:"assertions"`
	IsSafe       bool            `json:"is_safe"`
	Violations   []string        `json:"violations"`
	Timestamp    int64           `json:"timestamp"`
}

// SafetyGuestProgram simulates the execution context of the ZK guest program.
type SafetyGuestProgram struct {
	ImageID []byte
}

// NewSafetyGuestProgram creates a new instance of the guest program with a given ImageID.
func NewSafetyGuestProgram(imageID []byte) *SafetyGuestProgram {
	return &SafetyGuestProgram{
		ImageID: imageID,
	}
}

// Execute performs AST-like static analysis on the proposal content against the safety assertions.
// It returns a compiled SafetyJournal proving the safety status of the execution.
func (p *SafetyGuestProgram) Execute(proposal []byte, assertions SafetyAssertion) *SafetyJournal {
	var violations []string
	proposalStr := string(proposal)

	// 1. Check MaxFileSize
	if assertions.MaxFileSize > 0 && int64(len(proposal)) > assertions.MaxFileSize {
		violations = append(violations, fmt.Sprintf("proposal size %d exceeds limit of %d", len(proposal), assertions.MaxFileSize))
	}

	// 2. Check BannedImports
	for _, imp := range assertions.BannedImports {
		// Basic AST representation/text search matching:
		// match Go imports: import "imp" or import ( ... "imp" ... )
		// match JS/TS imports: import ... from 'imp', require('imp')
		goImportPattern := fmt.Sprintf(`"%s"`, imp)
		jsRequirePattern1 := fmt.Sprintf(`require('%s')`, imp)
		jsRequirePattern2 := fmt.Sprintf(`require("%s")`, imp)
		jsImportPattern1 := fmt.Sprintf(`from '%s'`, imp)
		jsImportPattern2 := fmt.Sprintf(`from "%s"`, imp)

		if strings.Contains(proposalStr, goImportPattern) ||
			strings.Contains(proposalStr, jsRequirePattern1) ||
			strings.Contains(proposalStr, jsRequirePattern2) ||
			strings.Contains(proposalStr, jsImportPattern1) ||
			strings.Contains(proposalStr, jsImportPattern2) {
			violations = append(violations, fmt.Sprintf("contains banned import: %s", imp))
		}
	}

	// 3. Check SandboxPaths
	if len(assertions.SandboxPaths) > 0 {
		// Look for path indicators in the text
		// If the proposal references absolute paths that do not start with any of the SandboxPaths,
		// we consider it a violation.
		words := strings.FieldsFunc(proposalStr, func(r rune) bool {
			return r == ' ' || r == '\n' || r == '\t' || r == '"' || r == '\'' || r == '`' || r == ',' || r == ';'
		})

		for _, word := range words {
			if strings.HasPrefix(word, "/") || strings.HasPrefix(word, "\\") {
				// Clean the path
				cleanWord := strings.TrimRight(word, ".:;()[]{}")
				isAllowed := false
				for _, sbPath := range assertions.SandboxPaths {
					if strings.HasPrefix(cleanWord, sbPath) {
						isAllowed = true
						break
					}
				}
				if !isAllowed && len(cleanWord) > 1 {
					violations = append(violations, fmt.Sprintf("attempts to reference path outside sandbox: %s", cleanWord))
				}
			}
		}
	}

	// 4. Check AllowNetwork
	if !assertions.AllowNetwork {
		networkKeywords := []string{
			"http://", "https://", "net.Dial", "net.Listen", "fetch(",
			"http.Get", "http.Post", "socket", "websocket",
		}
		for _, kw := range networkKeywords {
			if strings.Contains(proposalStr, kw) {
				violations = append(violations, fmt.Sprintf("violates network ban: found pattern %s", kw))
				break
			}
		}
	}

	proposalHash := sha256.Sum256(proposal)
	return &SafetyJournal{
		ProposalHash: proposalHash[:],
		Assertions:   assertions,
		IsSafe:       len(violations) == 0,
		Violations:   violations,
		Timestamp:    time.Now().Unix(),
	}
}

// ZKVMGuestSafetyChecker orchestrates safety attestation. It evaluates a proposal inside
// the simulated guest program and packages the result as a cryptographic ZKReceipt.
type ZKVMGuestSafetyChecker struct {
	ImageID []byte
	Program *SafetyGuestProgram
}

// NewZKVMGuestSafetyChecker initializes a safety checker with the given guest program ImageID.
func NewZKVMGuestSafetyChecker(imageID string) *ZKVMGuestSafetyChecker {
	imgBytes := []byte(imageID)
	return &ZKVMGuestSafetyChecker{
		ImageID: imgBytes,
		Program: NewSafetyGuestProgram(imgBytes),
	}
}

// Attest evaluates the proposal against assertions and returns a verifiable ZKReceipt.
// If mockFail is true, it simulates a cryptographic seal verification failure by generating an invalid seal.
func (c *ZKVMGuestSafetyChecker) Attest(ctx context.Context, proposal []byte, assertions SafetyAssertion, mockFail bool) (*ZKReceipt, error) {
	if len(proposal) == 0 {
		return nil, fmt.Errorf("proposal cannot be empty")
	}

	// Execute safety analysis inside the simulated Guest zkVM
	journal := c.Program.Execute(proposal, assertions)

	journalBytes, err := json.Marshal(journal)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal safety journal: %w", err)
	}

	// Construct seal. In a real RISC Zero zkVM execution, this is a STARK/SNARK proof.
	// We represent it as a mock signature verification block.
	var seal []byte
	if mockFail {
		seal = []byte("INVALID_SEAL")
	} else {
		// Valid seal: sha256 hash of (ImageID + JournalBytes)
		hasher := sha256.New()
		_, _ = hasher.Write(c.ImageID)
		_, _ = hasher.Write(journalBytes)
		seal = hasher.Sum(nil)
	}

	receipt := &ZKReceipt{
		ImageID: c.ImageID,
		Journal: journalBytes,
		Seal:    seal,
	}

	return receipt, nil
}
