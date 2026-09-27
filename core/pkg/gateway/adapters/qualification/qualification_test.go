package qualification

import "testing"

func TestRecordsNeverCountASkipAsAPass(t *testing.T) {
	suite := Suite{Adapter: "x", AdapterVersion: "1", SuiteVersion: "1", Cases: []SuiteCase{
		{ID: "a/1", Operation: "a"}, {ID: "a/2", Operation: "a"}, {ID: "b/1", Operation: "b"},
	}}
	records := suite.Records("env", map[string]CheckStatus{"a/1": CheckPass, "a/2": CheckSkipped, "b/1": CheckPass}, nil)
	if len(records) != 2 || records[0].Qualified || !records[1].Qualified {
		t.Fatalf("records %+v", records)
	}
	missing := suite.Records("env", map[string]CheckStatus{"a/1": CheckPass}, nil)
	if missing[0].Qualified || missing[1].Qualified || missing[1].Checks[0].Status != CheckSkipped {
		t.Fatalf("a case with no result counted: %+v", missing)
	}
	if records[0].SuiteDigest != suite.Digest() || len(suite.Digest()) != 64 {
		t.Fatal("the record does not carry the suite digest")
	}
	changed := suite
	changed.Cases = append([]SuiteCase{{ID: "a/1", Operation: "a", Description: "changed"}}, suite.Cases[1:]...)
	if changed.Digest() == suite.Digest() {
		t.Fatal("the digest does not cover the cases")
	}
}
