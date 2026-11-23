package verifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/tape"
)

func checkPolicyDecisionHashes(bundlePath string) CheckResult {
	// Verify that decision records expose a signed policy binding. Legacy
	// receipts use decision_hash. Current MCP proof receipts use the signed
	// EffectID, OutputHash (complete authorization evaluation), and ArgsHash
	// (raw authorization inputs), avoiding an unsigned compatibility field.
	pack := openPack(bundlePath)
	defer pack.close()
	receiptsDir, err := receiptDir(pack)
	if err != nil {
		return failed("policy_decision_hashes", err.Error())
	}
	if has, err := pack.hasDir(receiptsDir); err != nil || !has {
		if err != nil {
			return failed("policy_decision_hashes", fmt.Sprintf("cannot read receipts: %v", err))
		}
		// Already caught by lamport check, but note here too
		return CheckResult{Name: "policy_decision_hashes", Pass: false, Reason: "no receipts directory (checked receipts/ and 02_PROOFGRAPH/receipts/) — no policy decision binding to look for"}
	}

	entries, err := pack.readDir(receiptsDir)
	if err != nil || len(entries) == 0 {
		return CheckResult{Name: "policy_decision_hashes", Pass: false, Reason: "no receipt files to look for a policy decision binding in"}
	}

	// Structural check: parse each receipt and verify either the legacy field or
	// the current signed MCP policy-receipt binding exists.
	legacyVerified := 0
	legacyTotal := 0
	mcpPolicyTotal := 0
	mcpPolicyVerified := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := pack.readFile(receiptsDir + "/" + entry.Name())
		if err != nil {
			// A receipt the pack holds but that cannot be read safely (a link
			// out of the pack, a named pipe) is not one with no binding.
			return failed("policy_decision_hashes", fmt.Sprintf("cannot read receipt %s: %v", entry.Name(), err))
		}
		var receipt map[string]any
		if err := json.Unmarshal(data, &receipt); err != nil {
			continue
		}
		if strings.HasPrefix(firstString(receipt, "effect_id"), "mcp_policy_decision/") {
			mcpPolicyTotal++
			if firstString(receipt, "output_hash") != "" &&
				firstString(receipt, "args_hash") != "" &&
				firstString(receipt, "signature") != "" {
				mcpPolicyVerified++
			}
			continue
		}
		legacyTotal++
		if firstString(receipt, "decision_hash") != "" {
			legacyVerified++
		}
	}

	if mcpPolicyTotal > 0 {
		if mcpPolicyTotal != mcpPolicyVerified {
			return CheckResult{Name: "policy_decision_hashes", Pass: false, Reason: fmt.Sprintf("%d/%d MCP policy receipts lack an output_hash, args_hash or signature", mcpPolicyTotal-mcpPolicyVerified, mcpPolicyTotal)}
		}
		// Presence only. The signature over these fields is checked by
		// embedded_signature_trust; neither hash is recomputed here.
		return verified("policy_decision_hashes", fmt.Sprintf("%d MCP policy receipts carry output_hash, args_hash and signature fields; presence only, the hashes are not recomputed", mcpPolicyVerified))
	}

	if legacyVerified == 0 {
		return CheckResult{Name: "policy_decision_hashes", Pass: false, Reason: "no receipts contain a policy decision binding"}
	}

	return verified("policy_decision_hashes", fmt.Sprintf("%d of %d receipts carry a decision_hash field; presence only, the hash is not recomputed", legacyVerified, legacyTotal))
}

// checkReplayDeterminism checks the replay evidence a pack declares or
// carries. The rule:
//
//   - A pack that declares gate G2 in 00_INDEX.json claims replay evidence, so
//     all of it is required: 08_TAPES/tape_manifest.json and
//     02_PROOFGRAPH/determinism_manifest.json must be present and valid, the
//     tape must hold entries to replay, and 05_DIFFS must hold nothing but
//     empty placeholder files (a name that starts with "."). Anything missing
//     is FAILED; a tape with no entries replays nothing, which `replay`
//     reports as NOT_RUN.
//   - A tape that carries entries (rows in tape_manifest.json or entry_*.json
//     files) is replayed with tape.Tape.Replay, the code `helm-ai-kernel
//     replay` runs, whether or not G2 is declared, and every issue it finds
//     fails the check. Entry files without a tape manifest fail too.
//   - A pack that does not declare G2 is still checked on the replay material
//     it carries. A determinism manifest is the replay result: when present it
//     must parse and state equal live_hash and replay_hash, so diverging
//     hashes fail whether or not G2 is listed. A tape manifest must parse.
//     05_DIFFS is not read here: producers keep placeholders and other
//     artifacts in it, and only G2 makes its files replay differences.
//   - NOT_RUN only when G2 is not declared and the pack carries no
//     determinism manifest. A tape states no replay result, so it does not
//     make the check run; it is still replayed, fails if it does not replay,
//     and is named in the reason.
//   - A gates value that is not a list of gate names is malformed input and
//     FAILED: it cannot be read as "G2 is not declared".
//
// live_hash and replay_hash are the pack's own statements. Replaying the tape
// serves its recorded inputs back and compares them with their hashes and the
// manifest; it does not re-execute the run.
func checkReplayDeterminism(bundlePath string) CheckResult {
	const name = "replay_determinism"
	const (
		tapesDir     = "08_TAPES"
		tapeManifest = "08_TAPES/tape_manifest.json"
		detManifest  = "02_PROOFGRAPH/determinism_manifest.json"
	)
	pack := openPack(bundlePath)
	defer pack.close()
	declared, undeclared, err := replayGateDeclared(pack)
	if err != nil {
		return failed(name, err.Error())
	}

	hasTapesDir, err := pack.hasDir(tapesDir)
	if err != nil {
		return failed(name, fmt.Sprintf("%s is not read: %v", tapesDir, err))
	}
	hasTapeManifest, err := pack.hasFile(tapeManifest)
	if err != nil {
		return failed(name, fmt.Sprintf("%s is not read: %v", tapeManifest, err))
	}
	hasDetManifest, err := pack.hasFile(detManifest)
	if err != nil {
		return failed(name, fmt.Sprintf("%s is not read: %v", detManifest, err))
	}
	var entryFiles []string
	if hasTapesDir {
		if entryFiles, err = tape.EntryFileNames(pack.fs, tapesDir); err != nil {
			return failed(name, fmt.Sprintf("cannot list %s: %v", tapesDir, err))
		}
	}

	// established lists what was read and held.
	var established []string

	switch {
	case hasTapeManifest:
		manifestData, err := pack.readFile(tapeManifest)
		if err != nil {
			return failed(name, fmt.Sprintf("cannot read tape manifest: %v", err))
		}
		manifest, err := tape.ParseManifest(manifestData)
		if err != nil {
			return failed(name, fmt.Sprintf("invalid tape manifest JSON: %v", err))
		}
		if len(manifest.Entries) == 0 && len(entryFiles) == 0 {
			if declared {
				return failed(name, "gate G2 requires a tape to replay, and 08_TAPES/tape_manifest.json lists 0 entries with no entry files beside it, so nothing is replayed")
			}
			established = append(established, "tape_manifest.json parses and lists 0 entries (not replayed)")
			break
		}
		recorded, err := tape.LoadTape(pack.fs, tapesDir)
		if err != nil {
			return failed(name, fmt.Sprintf("the tape cannot be replayed: %v", err))
		}
		replayed, issues := recorded.Replay()
		if len(issues) > 0 {
			return failed(name, fmt.Sprintf("the tape does not replay: %d of %d tape entries replayed, %d issues: %s",
				replayed, len(recorded.Entries), len(issues), summarizeIssues(issues, 10)))
		}
		established = append(established, fmt.Sprintf("tape_manifest.json lists %d entries and the tape replays: %d of %d tape entries replayed through the tape replayer, "+
			"each matching its value_hash and tape_manifest.json (recorded inputs served back, the run is not re-executed)",
			len(manifest.Entries), replayed, len(recorded.Entries)))
	case len(entryFiles) > 0:
		return failed(name, fmt.Sprintf("08_TAPES holds %d entry files but no tape_manifest.json, so the tape cannot be replayed", len(entryFiles)))
	case !declared:
	case !hasTapesDir:
		return failed(name, "missing 08_TAPES directory — replay evidence required")
	default:
		return failed(name, "missing 08_TAPES/tape_manifest.json — replay evidence required")
	}

	switch {
	case hasDetManifest:
		detManifestData, err := pack.readFile(detManifest)
		if err != nil {
			return failed(name, fmt.Sprintf("cannot read determinism manifest: %v", err))
		}
		var detManifest map[string]any
		if err := json.Unmarshal(detManifestData, &detManifest); err != nil {
			return failed(name, fmt.Sprintf("invalid determinism manifest JSON: %v", err))
		}
		liveHash, liveOK := detManifest["live_hash"].(string)
		replayHash, replayOK := detManifest["replay_hash"].(string)
		if !liveOK || liveHash == "" || !replayOK || replayHash == "" {
			return failed(name, "determinism manifest must declare live_hash and replay_hash")
		}
		if liveHash != replayHash {
			return failed(name, fmt.Sprintf("replay hash divergence: live=%s replay=%s", liveHash, replayHash))
		}
		established = append(established, "determinism_manifest.json states equal live_hash and replay_hash (declared by the pack, not recomputed)")
	case !declared:
		// No replay result to compare. Say what is and is not there, so the
		// reason is true of a pack that carries a tape manifest.
		if !hasTapeManifest {
			return notRun(name, undeclared+", and the pack carries no replay material (no 08_TAPES/tape_manifest.json and no 02_PROOFGRAPH/determinism_manifest.json)")
		}
		return notRun(name, fmt.Sprintf("%s, and the pack carries no 02_PROOFGRAPH/determinism_manifest.json, so it states no replay result to compare; 08_TAPES/%s",
			undeclared, established[0]))
	default:
		return failed(name, "missing 02_PROOFGRAPH/determinism_manifest.json — replay hash proof required")
	}

	if !declared {
		notRead := "05_DIFFS is read as replay differences only under gate G2"
		if !hasTapeManifest {
			notRead = "the pack carries no 08_TAPES/tape_manifest.json; " + notRead
		}
		return verified(name, fmt.Sprintf("gate G2 is not declared; the replay material the pack carries is consistent with itself: %s. Not read: %s",
			strings.Join(established, "; "), notRead))
	}

	differences, err := replayDifferences(pack)
	if err != nil {
		return failed(name, fmt.Sprintf("cannot read 05_DIFFS: %v", err))
	}
	if len(differences) > 0 {
		return failed(name, "05_DIFFS contains replay differences: "+summarizeNames(differences, 5))
	}
	established = append(established, "05_DIFFS holds no files other than empty placeholders")
	return verified(name, "gate G2 evidence is present: "+strings.Join(established, "; "))
}

// replayDifferences lists what 05_DIFFS holds besides placeholders. A
// placeholder is an empty regular file whose name starts with ".", such as
// the .keep the launchpad writer creates. A missing 05_DIFFS holds nothing.
func replayDifferences(pack *packFiles) ([]string, error) {
	entries, err := pack.readDir("05_DIFFS")
	if absent(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var differences []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") && entry.Type().IsRegular() {
			if info, err := entry.Info(); err == nil && info.Size() == 0 {
				continue
			}
		}
		differences = append(differences, "05_DIFFS/"+entry.Name())
	}
	return differences, nil
}

// summarizeIssues joins up to limit issues and says how many it left out.
func summarizeIssues(issues []string, limit int) string {
	if len(issues) <= limit {
		return strings.Join(issues, "; ")
	}
	return fmt.Sprintf("%s; and %d more", strings.Join(issues[:limit], "; "), len(issues)-limit)
}

// replayGateDeclared reports whether 00_INDEX.json declares gate G2, which is
// how a pack states that it carries replay evidence. When it does not, the
// returned text says what the index declares instead. An index that cannot be
// read or parsed declares nothing either way, and neither does a gates value
// that is not a list of gate names: both are errors, not "G2 is not declared".
func replayGateDeclared(pack *packFiles) (bool, string, error) {
	hasIndex, err := pack.hasFile("00_INDEX.json")
	if err != nil {
		return false, "", fmt.Errorf("cannot read the gates 00_INDEX.json declares: %v", err)
	}
	if !hasIndex {
		return false, "pack has no 00_INDEX.json, so it declares no gates", nil
	}

	data, err := pack.readFile("00_INDEX.json")
	if err != nil {
		return false, "", fmt.Errorf("cannot read the gates 00_INDEX.json declares: %v", err)
	}

	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil {
		return false, "", fmt.Errorf("cannot parse the gates 00_INDEX.json declares: %v", err)
	}

	raw, present := document["gates"]
	// Producers that hold the gates in a nil list write null.
	if !present || string(bytes.TrimSpace(raw)) == "null" {
		return false, "00_INDEX.json declares no gates", nil
	}
	var gates []string
	if err := json.Unmarshal(raw, &gates); err != nil {
		return false, "", fmt.Errorf("00_INDEX.json gates must be a list of gate names such as [\"G0\",\"G2\"]; it is malformed, so the gates the pack declares cannot be read: %v", err)
	}
	if slices.Contains(gates, "G2") {
		return true, "", nil
	}
	return false, "00_INDEX.json gates do not declare G2", nil
}
