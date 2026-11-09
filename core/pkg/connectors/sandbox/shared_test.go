package sandbox

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidIDRefusesWhatCouldEscapeAPathOrACommandLine(t *testing.T) {
	for _, ok := range []string{"sbx-1", "i3x9k2.m", "A_b-c.d", strings.Repeat("a", 128)} {
		assert.True(t, ValidID(ok), ok)
	}
	for _, bad := range []string{"", "-rf", ".hidden", "a/b", "../x", "a b", "a;b", "a\nb", "a%2fb", "a?x=1", "é", strings.Repeat("a", 129)} {
		assert.False(t, ValidID(bad), bad)
	}
}

func TestShellJoinRunsTheOriginalArgumentVector(t *testing.T) {
	argv := []string{"printf", "%s|%s|%s", `it's "q"`, "$(echo pwned)", "a;b\nc"}
	out, err := exec.Command("sh", "-c", ShellJoin(argv)).Output() // #nosec G204 -- the test of quoting
	require.NoError(t, err)
	assert.Equal(t, "it's \"q\"|$(echo pwned)|a;b\nc", string(out))
	assert.Equal(t, "''", ShellJoin([]string{""}))
}

func serve(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func TestDoJSONClassifiesEveryAnswer(t *testing.T) {
	const key = "sk-secret"
	for name, tc := range map[string]struct {
		handler  http.HandlerFunc
		limit    int64
		refused  bool
		drift    bool
		tooLarge bool
		status   int
		ok       bool
	}{
		"ok":        {handler: func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"id":"x"}`)) }, ok: true},
		"4xx":       {handler: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(422); _, _ = w.Write([]byte(key)) }, refused: true, status: 422},
		"5xx":       {handler: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }, status: 503},
		"garbage":   {handler: func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`<html>`)) }, drift: true, status: 200},
		"too large": {handler: func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(strings.Repeat("x", 100))) }, limit: 10, tooLarge: true, status: 200},
		"redirect":  {handler: func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "http://127.0.0.1:1/x", 307) }, status: 307},
	} {
		t.Run(name, func(t *testing.T) {
			srv := serve(t, tc.handler)
			var out struct {
				ID string `json:"id"`
			}
			err := DoJSON(context.Background(), Call{Client: srv.Client(), Provider: "p", Method: "POST", URL: srv.URL + "/a/b?token=" + key,
				Auth: func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+key) }, Body: map[string]string{"a": "b"}, Out: &out, Limit: tc.limit})
			if tc.ok {
				require.NoError(t, err)
				assert.Equal(t, "x", out.ID)
				return
			}
			ce := AsCallError(err)
			require.NotNil(t, ce, "%v", err)
			assert.Equal(t, tc.refused, ce.Refused)
			assert.Equal(t, tc.drift, ce.Drift)
			assert.Equal(t, tc.tooLarge, ce.TooLarge)
			assert.Equal(t, tc.status, ce.Status)
			assert.NotContains(t, err.Error(), key, "an error never carries a body or a credential")
		})
	}
}

func TestDoJSONTransportFailureIsNotRefused(t *testing.T) {
	srv := serve(t, func(http.ResponseWriter, *http.Request) {})
	url := srv.URL
	srv.Close()
	err := DoJSON(context.Background(), Call{Provider: "p", Method: "GET", URL: url + "/x?secret=abc"})
	ce := AsCallError(err)
	require.NotNil(t, ce)
	assert.False(t, ce.Refused)
	assert.NotContains(t, err.Error(), "secret=abc", "the query string stays out of the error")
}

func TestDoJSONDoesNotFollowARedirectWithTheCredential(t *testing.T) {
	var seen int
	other := serve(t, func(http.ResponseWriter, *http.Request) { seen++ })
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, other.URL, http.StatusFound) })
	err := DoJSON(context.Background(), Call{Provider: "p", Method: "GET", URL: srv.URL, Auth: func(r *http.Request) { r.Header.Set("Authorization", "Bearer k") }})
	require.Error(t, err)
	assert.Zero(t, seen)
}

func TestDoJSONRawBodiesAreBoundedToo(t *testing.T) {
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			assert.Equal(t, "application/octet-stream", r.Header.Get("Content-Type"))
			return
		}
		_, _ = w.Write([]byte("0123456789"))
	})
	var raw []byte
	require.NoError(t, DoJSON(context.Background(), Call{Client: srv.Client(), Provider: "p", Method: "GET", URL: srv.URL, RawOut: &raw}))
	assert.Equal(t, "0123456789", string(raw))
	err := DoJSON(context.Background(), Call{Client: srv.Client(), Provider: "p", Method: "GET", URL: srv.URL, RawOut: &raw, Limit: 5})
	require.NotNil(t, AsCallError(err))
	assert.True(t, AsCallError(err).TooLarge)
	require.NoError(t, DoJSON(context.Background(), Call{Client: srv.Client(), Provider: "p", Method: "PUT", URL: srv.URL, RawBody: []byte("abc")}))
}
