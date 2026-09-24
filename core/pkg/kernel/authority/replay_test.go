package authority

import (
	"encoding/json"
	"flag"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
)

var updateReplay = flag.Bool("update", false, "rewrite testdata/replay.json with the current decisions")

const replayCorpus = "testdata/replay.json"

type replayFile struct {
	Profile        string       `json:"profile,omitempty"`
	SnapshotDigest string       `json:"snapshot_digest,omitempty"`
	Policy         prg.Graph    `json:"policy"`
	Cases          []replayCase `json:"cases"`
}

type replayCase struct {
	Name  string    `json:"name"`
	Input Input     `json:"input"`
	Want  *Decision `json:"want,omitempty"`
}

// TestReplayCorpus re-runs Decide over stored inputs and requires the stored
// decisions back exactly. The corpus also pins the evaluation profile and the
// snapshot digest, so a change to evaluation semantics fails here until the
// corpus is regenerated on purpose (go test -run TestReplayCorpus -update).
func TestReplayCorpus(t *testing.T) {
	raw, err := os.ReadFile(replayCorpus)
	require.NoError(t, err)
	var corpus replayFile
	require.NoError(t, json.Unmarshal(raw, &corpus))
	require.NotEmpty(t, corpus.Cases)

	s, err := Compile(&corpus.Policy)
	require.NoError(t, err)

	if *updateReplay {
		corpus.Profile = Profile
		corpus.SnapshotDigest = s.Digest()
		for i := range corpus.Cases {
			d := Decide(corpus.Cases[i].Input, s)
			corpus.Cases[i].Want = &d
		}
		out, err := json.MarshalIndent(corpus, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(replayCorpus, append(out, '\n'), 0o600))
		return
	}

	require.Equal(t, corpus.Profile, Profile, "evaluation profile changed; regenerate the corpus deliberately")
	require.Equal(t, corpus.SnapshotDigest, s.Digest(), "snapshot digest changed for identical policy content")
	for _, tc := range corpus.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			require.NotNil(t, tc.Want, "case has no stored decision")
			require.Equal(t, *tc.Want, Decide(tc.Input, s))
		})
	}
}
