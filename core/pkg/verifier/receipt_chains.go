package verifier

import (
	"encoding/json"
	"fmt"
	"math"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/receiptverify"
)

func checkChainIntegrity(bundlePath string) CheckResult {
	// Look for proofgraph.json or 02_PROOFGRAPH/
	pack := openPack(bundlePath)
	defer pack.close()
	hasGraph, err := pack.hasFile("proofgraph.json")
	if err != nil {
		return failed("chain_integrity", fmt.Sprintf("proofgraph.json is not read: %v", err))
	}
	hasGraphDir, err := pack.hasDir("02_PROOFGRAPH")
	if err != nil {
		return failed("chain_integrity", fmt.Sprintf("02_PROOFGRAPH is not read: %v", err))
	}

	if !hasGraph && !hasGraphDir {
		return CheckResult{
			Name:   "chain_integrity",
			Pass:   false,
			Reason: "missing proof graph: neither proofgraph.json nor 02_PROOFGRAPH/ found — chain integrity cannot be verified",
		}
	}

	if hasGraph {
		data, err := pack.readFile("proofgraph.json")
		if err != nil {
			return CheckResult{Name: "chain_integrity", Pass: false, Reason: fmt.Sprintf("cannot read proofgraph: %v", err)}
		}
		var pg map[string]any
		if err := json.Unmarshal(data, &pg); err != nil {
			return CheckResult{Name: "chain_integrity", Pass: false, Reason: fmt.Sprintf("invalid proofgraph JSON: %v", err)}
		}
	}

	// The proof graph being present and parseable was, until now, the entire
	// check — it never read prev_hash and never walked a parent, so a chain with
	// its middle removed, its order changed, or a fork grafted on reported
	// "chain integrity: PASS" (F-03). Actually link the receipts.
	receipts, err := receiptDir(pack)
	if err != nil {
		return failed("chain_integrity", err.Error())
	}
	if !packClaimsAChain(pack, receipts) {
		return unchainedPackResult(pack, "chain_integrity", receipts)
	}
	chains, res := loadReceiptChains(bundlePath, "chain_integrity")
	if res != nil {
		return *res
	}

	linked := 0
	for _, chain := range chains {
		// linkChain already proved each node's prev_hash resolves to the chain
		// hash of its predecessor, that there is exactly one genesis, no forks,
		// no cycles and no orphans. Re-assert the linkage explicitly so the
		// invariant is stated where a reader looks for it.
		for i := 1; i < len(chain.ordered); i++ {
			prev := chain.ordered[i-1]
			cur := chain.ordered[i]
			if !prev.matches(cur.receipt) {
				return CheckResult{
					Name: "chain_integrity", Pass: false,
					Reason: fmt.Sprintf("session %q: receipt %s prev_hash=%s does not match the chain hash of %s (%s)",
						chain.sessionID, cur.receipt.ReceiptID, cur.receipt.PrevHash, prev.receipt.ReceiptID, prev.primary()),
				}
			}
		}
		linked += len(chain.ordered)
	}

	return CheckResult{
		Name: "chain_integrity", Pass: true,
		Detail: fmt.Sprintf("%d receipts across %d session chain(s) link genesis-to-head with no fork, gap, or cycle", linked, len(chains)),
	}
}

// checkLamportMonotonicity verifies that each receipt chain carries strictly
// increasing Lamport clocks, and that the genesis receipt starts at 1.
//
// This previously returned Pass with "%d receipt files present" straight from
// os.ReadDir — no clock was ever parsed, so any ordering claim passed (F-03).
func checkLamportMonotonicity(bundlePath string) CheckResult {
	pack := openPack(bundlePath)
	defer pack.close()
	receipts, err := receiptDir(pack)
	if err != nil {
		return failed("lamport_monotonicity", err.Error())
	}
	if !packClaimsAChain(pack, receipts) {
		return unchainedPackResult(pack, "lamport_monotonicity", receipts)
	}
	chains, res := loadReceiptChains(bundlePath, "lamport_monotonicity")
	if res != nil {
		return *res
	}

	checked := 0
	for _, chain := range chains {
		for i, r := range chain.ordered {
			if i == 0 {
				if r.receipt.LamportClock != 1 {
					return CheckResult{
						Name: "lamport_monotonicity", Pass: false,
						Reason: fmt.Sprintf("session %q genesis receipt %s has lamport_clock=%d, want 1 — the chain head is missing",
							chain.sessionID, r.receipt.ReceiptID, r.receipt.LamportClock),
					}
				}
				checked++
				continue
			}
			prev := chain.ordered[i-1].receipt
			if r.receipt.LamportClock != prev.LamportClock+1 {
				return CheckResult{
					Name: "lamport_monotonicity", Pass: false,
					Reason: fmt.Sprintf("session %q: receipt %s has lamport_clock=%d after %d — chain is truncated, reordered, or has a gap",
						chain.sessionID, r.receipt.ReceiptID, r.receipt.LamportClock, prev.LamportClock),
				}
			}
			checked++
		}
	}

	return CheckResult{
		Name: "lamport_monotonicity", Pass: true,
		Detail: fmt.Sprintf("%d receipts across %d session chain(s) are strictly monotonic from genesis", checked, len(chains)),
	}
}

// receiptNode pairs a parsed receipt with the chain hash other receipts use to
// reference it.
type receiptNode struct {
	receipt *contracts.Receipt
	// hashes are the identities a successor's prev_hash may legitimately carry.
	// EvidencePack producers do not agree on one derivation:
	//   - store     chains on contracts.ReceiptChainHash (JCS over the receipt)
	//   - mcp-proof chains on "sha256:"+sha256 of the receipt file as written
	//   - demo      chains on a "hash" field the receipt declares about itself
	// The first two are recomputed here, so tampering breaks linkage. The third
	// has no specified preimage and cannot be recomputed — recorded in the
	// security ledger as a schema gap (F-20) — so it is kept in declared, apart.
	hashes   []string
	declared string
	file     string
}

// normalizeHash strips the optional "sha256:" prefix so identities produced by
// different producers compare equal.
func normalizeHash(h string) string {
	return strings.TrimPrefix(strings.TrimSpace(h), "sha256:")
}

// matches reports whether succ's prev_hash refers to this node. A receipt.v5
// successor signs its prev_hash, so it links only to an identity recomputed
// here: anyone can write a declared hash, and an unsigned stand-in declaring a
// deleted receipt's hash would close the gap (helm-tracker#305).
func (n receiptNode) matches(succ *contracts.Receipt) bool {
	want := normalizeHash(succ.PrevHash)
	if want == "" {
		return false
	}
	for _, h := range n.hashes {
		if normalizeHash(h) == want {
			return true
		}
	}
	if succ.SignatureVersion != contracts.ReceiptSignatureV5 && n.declared != "" {
		return normalizeHash(n.declared) == want
	}
	return false
}

// primary is the identity quoted in diagnostics.
func (n receiptNode) primary() string {
	if len(n.hashes) == 0 {
		return ""
	}
	return normalizeHash(n.hashes[0])
}

// receiptChain is one session's receipts ordered from genesis to head.
type receiptChain struct {
	sessionID string
	ordered   []receiptNode
}

// loadReceiptChains parses every receipt in the pack, groups them by session,
// and links each group into a single chain by walking prev_hash from genesis.
//
// It returns a non-nil CheckResult when the receipts cannot be loaded or the
// chain does not link, so callers surface the failure under their own name.
func loadReceiptChains(bundlePath, checkName string) ([]receiptChain, *CheckResult) {
	fail := func(format string, args ...any) (
		[]receiptChain, *CheckResult) {
		return nil, &CheckResult{Name: checkName, Pass: false, Reason: fmt.Sprintf(format, args...)}
	}

	pack := openPack(bundlePath)
	defer pack.close()
	receiptsDir, err := receiptDir(pack)
	if err != nil {
		return fail("%v", err)
	}
	if has, err := pack.hasDir(receiptsDir); err != nil || !has {
		if err != nil {
			return fail("cannot read receipts: %v", err)
		}
		return fail("missing receipts directory (checked receipts/ and 02_PROOFGRAPH/receipts/) — chain of custody cannot be verified")
	}
	entries, err := pack.readDir(receiptsDir)
	if err != nil {
		return fail("cannot read receipts: %v", err)
	}

	bySession := map[string][]receiptNode{}
	total := 0
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := pack.readFile(receiptsDir + "/" + entry.Name())
		if err != nil {
			return fail("cannot read receipt %s: %v", entry.Name(), err)
		}
		// encoding/json binds a member spelled in another letter case to the
		// field: "PREV_HASH" would link a chain whose signed prev_hash does
		// not (helm-tracker#305).
		if err := receiptverify.ValidateReceiptMemberNames(data); err != nil {
			return fail("receipt %s is refused: %v", entry.Name(), err)
		}
		var receipt contracts.Receipt
		if err := json.Unmarshal(data, &receipt); err != nil {
			return fail("receipt %s is not valid JSON: %v", entry.Name(), err)
		}

		// EvidencePacks carry more than one receipt schema, and they do not
		// agree on how a node is identified:
		//
		//   - store.buildNextCausalReceipt chains contracts.Receipt on
		//     contracts.ReceiptChainHash (JCS over the receipt minus its
		//     transparency fields).
		//   - demo/mcp-proof/financedemo receipts carry their own "hash" field
		//     and chain children on that value directly.
		//
		// A receipt.v5 successor links only to an identity derived here; a
		// successor with no signature_version may also link to the declared hash.
		//
		// Caveat recorded in the security ledger: a self-declared "hash" cannot
		// be recomputed by the verifier, because its preimage is not specified
		// anywhere. For those receipts this proves the chain is well-formed, not
		// that each node's contents are bound to its identity.
		var raw map[string]any
		if err := json.Unmarshal(data, &raw); err != nil {
			return fail("receipt %s is not a JSON object: %v", entry.Name(), err)
		}

		var hashes []string
		// Recomputed identities first, so diagnostics quote a verifiable value.
		if h, hErr := contracts.ReceiptChainHash(&receipt); hErr == nil {
			hashes = append(hashes, h)
		}
		hashes = append(hashes, "sha256:"+sha256Hex(data))
		declared, _ := raw["hash"].(string)
		declared = strings.TrimSpace(declared)

		// Lamport lives under different keys across the schemas.
		if receipt.LamportClock == 0 {
			// Reject a non-integral or negative clock rather than truncating it:
			// uint64(1.9) is 1, which would let a tampered receipt slot into an
			// ordering it does not actually occupy.
			if v, ok := raw["lamport"].(float64); ok {
				if v != math.Trunc(v) || v < 0 {
					return fail("receipt %s has a non-integral lamport clock %v", entry.Name(), v)
				}
				receipt.LamportClock = uint64(v)
			}
		}
		if receipt.ReceiptID == "" {
			receipt.ReceiptID, _ = raw["receipt_id"].(string)
		}

		// Only receipt.v5 binds SessionID in its signing envelope. Legacy
		// receipts retain their historical ExecutorID chain scope even when a
		// later storage migration has populated session_id for lookup purposes.
		session := receipt.ExecutorID
		if receipt.SignatureVersion == contracts.ReceiptSignatureV5 {
			session = receipt.SessionID
		}
		bySession[session] = append(bySession[session], receiptNode{
			receipt: &receipt, hashes: hashes, declared: declared, file: entry.Name(),
		})
		total++
	}

	if total == 0 {
		return fail("receipts directory contains no receipts — no chain of custody to verify")
	}

	chains := make([]receiptChain, 0, len(bySession))
	for session, nodes := range bySession {
		ordered, err := linkChain(nodes)
		if err != nil {
			return fail("session %q: %v", session, err)
		}
		chains = append(chains, receiptChain{sessionID: session, ordered: ordered})
	}
	sort.Slice(chains, func(i, j int) bool { return chains[i].sessionID < chains[j].sessionID })
	return chains, nil
}

// linkChain orders one session's receipts by following prev_hash from the
// genesis receipt, and rejects forks, cycles, orphans and truncation.
func linkChain(nodes []receiptNode) ([]receiptNode, error) {
	// Genesis is the receipt with an empty prev_hash. Exactly one is required:
	// zero means the head of the chain was removed, more than one means the
	// chain was forked at the root.
	var roots []receiptNode
	for _, n := range nodes {
		if normalizeHash(n.receipt.PrevHash) == "" {
			roots = append(roots, n)
		}
	}
	switch {
	case len(roots) == 0:
		return nil, fmt.Errorf("no genesis receipt (none has an empty prev_hash) — the start of the chain is missing")
	case len(roots) > 1:
		return nil, fmt.Errorf("%d receipts claim to be genesis — the chain is forked at the root", len(roots))
	}

	ordered := make([]receiptNode, 0, len(nodes))
	used := map[string]bool{}
	current := roots[0]
	for {
		ordered = append(ordered, current)
		used[current.file] = true

		var children []receiptNode
		for _, n := range nodes {
			if used[n.file] {
				continue
			}
			if current.matches(n.receipt) {
				children = append(children, n)
			}
		}
		if len(children) == 0 {
			break
		}
		if len(children) > 1 {
			return nil, fmt.Errorf("receipt %s has %d successors — the chain is forked",
				current.receipt.ReceiptID, len(children))
		}
		current = children[0]
		if len(ordered) > len(nodes) {
			return nil, fmt.Errorf("receipt chain contains a cycle")
		}
	}

	if len(ordered) != len(nodes) {
		// Unreached receipts point at a predecessor that is not in the pack —
		// exactly what deleting a middle receipt produces.
		var orphans []string
		for _, n := range nodes {
			if !used[n.file] {
				orphans = append(orphans, fmt.Sprintf("%s (prev_hash=%s)", n.receipt.ReceiptID, n.receipt.PrevHash))
			}
		}
		sort.Strings(orphans)
		return nil, fmt.Errorf("%d of %d receipts are unreachable from genesis — the chain is broken or truncated: %s",
			len(orphans), len(nodes), strings.Join(orphans, ", "))
	}

	return ordered, nil
}

// packClaimsAChain reports whether the pack should be held to the full
// genesis-to-head walk.
//
// That is true when any receipt carries a non-empty prev_hash, and also — fail
// closed — when the receipts directory is missing or empty, or when any receipt
// cannot be read or parsed. Only a directory of well-formed receipts that all
// lack prev_hash counts as "no chain claimed".
//
// Several producers (launchpad, conform) emit receipts with lamport clocks that
// imply an order but no prev_hash linking them — those packs assert no chain of
// custody at all. Verifying such a pack must neither invent a chain nor claim to
// have checked one. Packs that DO carry prev_hash values get the full
// genesis-to-head walk.
//
// This cannot be abused to bypass the check: stripping every prev_hash changes
// what the pack claims, and the report says so in plain text instead of
// reporting a verified chain. A missing or empty receipts directory is not "no
// chain claimed" — it is a pack with no evidence, so it falls through and fails.
func packClaimsAChain(pack *packFiles, receiptsDir string) bool {
	if has, err := pack.hasDir(receiptsDir); err != nil || !has {
		return true
	}
	entries, err := pack.readDir(receiptsDir)
	if err != nil {
		return true
	}
	receipts := 0
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		receipts++
		data, err := pack.readFile(receiptsDir + "/" + entry.Name())
		if err != nil {
			// An unreadable receipt must not be read as "no chain claimed" —
			// that would let a corrupt or deliberately unreadable file skip the
			// walk entirely. Claim a chain so the caller falls through to
			// loadReceiptChains and fails there with the real reason.
			return true
		}
		var raw map[string]any
		if json.Unmarshal(data, &raw) != nil {
			return true
		}
		if s, _ := raw["prev_hash"].(string); strings.TrimSpace(s) != "" {
			return true
		}
	}
	return receipts == 0
}

// unchainedPackResult describes a pack that makes no chaining claim. There is
// no chain to walk, so the check did not run; it used to be counted as passed.
func unchainedPackResult(pack *packFiles, checkName, receiptsDir string) CheckResult {
	entries, _ := pack.readDir(receiptsDir)
	n := 0
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			n++
		}
	}
	return notRun(checkName, fmt.Sprintf("%d receipts carry no prev_hash: this pack asserts no chain of custody, "+
		"so there is no chain to check", n))
}
